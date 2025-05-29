package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	// "encoding/json"
	"fmt"
	"image/png"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// --- 配置 ---
var (
	dbClient             *gorm.DB
	redisClient          *redis.Client
	jwtSecretKey         = []byte(getEnv("JWT_SECRET_KEY", "your-secret-key-for-access-tokens"))
	jwtRefreshSecretKey  = []byte(getEnv("JWT_REFRESH_SECRET_KEY", "your-secret-key-for-refresh-tokens"))
	accessTokenDuration  = time.Minute * 15   // 访问令牌有效期
	refreshTokenDuration = time.Hour * 24 * 7 // 刷新令牌有效期
	totpIssuer           = "MyApp"            // TOTP 发行者名称
	totpTempStorePrefix  = "totp_temp_secret:" // Redis 中临时 TOTP 密钥的前缀
	refreshTokenPrefix   = "refresh_token:"   // Redis 中刷新令牌的前缀
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// --- 模型 ---
type User struct {
	ID            uuid.UUID `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
	Username      string    `gorm:"uniqueIndex;not null" json:"username"`
	Email         string    `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash  string    `gorm:"not null" json:"-"` 
	TOTPSecret    string    `json:"-"`                 
	IsTOTPEnabled bool      `gorm:"default:false" json:"is_totp_enabled"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type TrustedDevice struct {
	ID          uuid.UUID `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
	UserID      uuid.UUID `gorm:"type:uuid;not null;index:idx_user_device,unique" json:"user_id"` // Foreign key to User
	DeviceID    string    `gorm:"not null;index:idx_user_device,unique" json:"device_id"`      // Unique identifier for the device, sent by client
	Description string    `json:"description,omitempty"`                                       // e.g., "Electron App on John's Macbook"
	CreatedAt   time.Time `json:"created_at"`
	LastUsedAt  time.Time `json:"last_used_at"`
	User        User      `gorm:"foreignKey:UserID"` // Belongs to User
}

// --- 数据库初始化 ---
func InitDB() {
	dsn := getEnv("DATABASE_URL", "host=localhost user=user password=password dbname=authdb port=5432 sslmode=disable TimeZone=Asia/Shanghai")
	var err error
	dbClient, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("无法连接到 PostgreSQL: %v", err)
	}
	log.Println("成功连接到 PostgreSQL")

	err = dbClient.AutoMigrate(&User{}, &TrustedDevice{}) // Added TrustedDevice
	if err != nil {
		log.Fatalf("无法迁移数据库模式: %v", err)
	}
	log.Println("数据库迁移完成")
}

func InitRedis() {
	redisAddr := getEnv("REDIS_URL", "localhost:6379")
	redisClient = redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})
	_, err := redisClient.Ping(context.Background()).Result()
	if err != nil {
		log.Fatalf("无法连接到 Redis: %v", err)
	}
	log.Println("成功连接到 Redis")
}

// --- JWT 工具 ---
type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

func generateJWT(userID uuid.UUID, secretKey []byte, duration time.Duration) (string, error) {
	expirationTime := time.Now().Add(duration)
	claims := &Claims{
		UserID: userID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    totpIssuer,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

func generateAccessAndRefreshTokens(userID uuid.UUID) (string, string, error) {
	accessToken, err := generateJWT(userID, jwtSecretKey, accessTokenDuration)
	if err != nil {
		return "", "", err
	}
	refreshToken, err := generateJWT(userID, jwtRefreshSecretKey, refreshTokenDuration)
	if err != nil {
		return "", "", err
	}

	err = redisClient.Set(context.Background(), refreshTokenPrefix+refreshToken, userID.String(), refreshTokenDuration).Err()
	if err != nil {
		return "", "", fmt.Errorf("无法存储刷新令牌到 Redis: %v", err)
	}

	return accessToken, refreshToken, nil
}

func validateToken(tokenString string, secretKey []byte) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("无效的令牌")
	}
	return claims, nil
}

// --- TOTP 工具 ---
func generateTOTPSecret() string {
	key := make([]byte, 20)
	_, _ = rand.Read(key)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
}

func generateTOTPQRCode(username, secret string) (string, error) {
	key, err := otp.NewKeyFromURL(fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		totpIssuer, username, secret, totpIssuer))
	if err != nil {
		return "", fmt.Errorf("无法生成 OTP 密钥 URL: %v", err)
	}
	return key.String(), nil 
}

func validateTOTP(secret, code string) bool {
	valid, _ := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return valid
}

// --- 密码工具 ---
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// --- 中间件 ---
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "请求未包含授权头"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "授权头格式不正确"})
			c.Abort()
			return
		}
		tokenString := parts[1]

		claims, err := validateToken(tokenString, jwtSecretKey)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的访问令牌", "details": err.Error()})
			c.Abort()
			return
		}

		userID, err := uuid.Parse(claims.UserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "无法解析用户ID"})
			c.Abort()
			return
		}
		c.Set("userID", userID)
		c.Next()
	}
}

// --- API 处理器 ---
// POST /register
type RegisterInput struct {
	Username string `json:"username" binding:"required,min=3"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

func RegisterHandler(c *gin.Context) {
	var input RegisterInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := hashPassword(input.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法加密密码"})
		return
	}

	user := User{
		Username:     input.Username,
		Email:        input.Email,
		PasswordHash: hashedPassword,
	}

	var existingUser User
	if err := dbClient.Where("username = ? OR email = ?", input.Username, input.Email).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "用户名或邮箱已存在"})
		return
	} else if err != gorm.ErrRecordNotFound {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库查询失败", "details": err.Error()})
		return
	}

	if err := dbClient.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法创建用户", "details": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "用户注册成功", "user_id": user.ID})
}

// POST /login
type LoginInput struct {
	Username       string `json:"username" binding:"required"`
	Password       string `json:"password" binding:"required"`
	DeviceID       string `json:"device_id,omitempty"`       // Client will send this
	RememberDevice bool   `json:"remember_device,omitempty"` // For non-2FA users, or if client wants to suggest remembering
}

type LoginResponse struct {
	Message       string `json:"message,omitempty"`
	AccessToken   string `json:"access_token,omitempty"`
	RefreshToken  string `json:"refresh_token,omitempty"`
	TOTPRequired  bool   `json:"totp_required,omitempty"`
	UserID        string `json:"user_id,omitempty"`        // For client to pass to TOTP verify
	DeviceID      string `json:"device_id,omitempty"`      // For client to pass to TOTP verify if it was part of initial login
	TrustedDevice bool   `json:"trusted_device,omitempty"` // True if login was successful because device is trusted
}

func LoginHandler(c *gin.Context) {
	var input LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	if err := dbClient.Where("username = ?", input.Username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误", "details": err.Error()})
		return
	}

	if !checkPasswordHash(input.Password, user.PasswordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	// Device Trust Check
	if input.DeviceID != "" {
		var trustedDevice TrustedDevice
		if err := dbClient.Where("user_id = ? AND device_id = ?", user.ID, input.DeviceID).First(&trustedDevice).Error; err == nil {
			// Device is trusted
			log.Printf("用户 %s 从受信任的设备 %s 登录", user.Username, input.DeviceID)
			trustedDevice.LastUsedAt = time.Now()
			if err := dbClient.Save(&trustedDevice).Error; err != nil {
				log.Printf("警告: 无法更新受信任设备的 LastUsedAt: %v", err)
				// Continue login, not a fatal error for this flow
			}

			accessToken, refreshToken, err := generateAccessAndRefreshTokens(user.ID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "无法生成令牌", "details": err.Error()})
				return
			}
			c.JSON(http.StatusOK, LoginResponse{
				Message:       "从受信任的设备成功登录",
				AccessToken:   accessToken,
				RefreshToken:  refreshToken,
				TrustedDevice: true,
			})
			return
		}
		// if err != gorm.ErrRecordNotFound {
		// 	log.Printf("检查受信任设备时数据库出错: %v", err)
		// 	// Potentially continue as if device is not trusted, or return error
		// }	
	}

	// Device not trusted or no DeviceID provided, proceed with normal flow
	if user.IsTOTPEnabled {
		log.Printf("用户 %s 需要 TOTP 验证，设备 ID: %s", user.Username, input.DeviceID)
		c.JSON(http.StatusOK, LoginResponse{
			Message:      "需要 TOTP 验证",
			TOTPRequired: true,
			UserID:       user.ID.String(),
			DeviceID:     input.DeviceID, // Pass DeviceID for the TOTP verification step
		})
		return
	}

	// TOTP Not Enabled, and device not pre-trusted (or no DeviceID)
	accessToken, refreshToken, err := generateAccessAndRefreshTokens(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法生成令牌", "details": err.Error()})
		return
	}

	// If user chose to remember this device (and 2FA is not enabled)
	if input.RememberDevice && input.DeviceID != "" {
		log.Printf("用户 %s (未启用TOTP) 选择记住设备 %s", user.Username, input.DeviceID)
		newTrustedDevice := TrustedDevice{
			UserID:     user.ID,
			DeviceID:   input.DeviceID,
			LastUsedAt: time.Now(),
			// Description: "Automatically remembered", // Client could provide a better one
		}
		// Using FirstOrCreate to handle potential race conditions or re-attempts
		if err := dbClient.Where(TrustedDevice{UserID: user.ID, DeviceID: input.DeviceID}).
			Assign(TrustedDevice{LastUsedAt: time.Now()}).
			FirstOrCreate(&newTrustedDevice).Error; err != nil {
			log.Printf("警告: 无法为非 TOTP 用户保存受信任的设备 %s: %v", input.DeviceID, err)
			// Not a fatal error for login itself
		}
	}

	c.JSON(http.StatusOK, LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// POST /login/verify-totp
type VerifyTOTPInput struct {
	UserID         string `json:"user_id" binding:"required"`
	Code           string `json:"code" binding:"required,len=6"`
	DeviceID       string `json:"device_id,omitempty"`       // Sent by client if it was part of initial login
	RememberDevice bool   `json:"remember_device,omitempty"` // Client indicates if user wants to trust this device
}

func VerifyTOTPLoginHandler(c *gin.Context) {
	var input VerifyTOTPInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, err := uuid.Parse(input.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的用户ID格式"})
		return
	}

	var user User
	if err := dbClient.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "找不到用户"})
		return
	}

	if !user.IsTOTPEnabled || user.TOTPSecret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该用户未启用 TOTP 或密钥未设置"})
		return
	}

	if !validateTOTP(user.TOTPSecret, input.Code) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的 TOTP 码"})
		return
	}

	// TOTP 验证成功
	// If "Remember Device" is checked and DeviceID is provided, save it
	if input.RememberDevice && input.DeviceID != "" {
		log.Printf("用户 %s 在 TOTP 验证后选择记住设备 %s", user.Username, input.DeviceID)
		trustedDevice := TrustedDevice{
			UserID:     user.ID,
			DeviceID:   input.DeviceID,
			LastUsedAt: time.Now(),
			// Description: "Electron App via TOTP", // Client could send a better description
		}
		// Use FirstOrCreate to handle if device was somehow added by another flow, or update LastUsedAt
		// Or use .Clauses(clause.OnConflict{DoNothing: true}).Create(&trustedDevice) if you only want to add if new
		if err := dbClient.Where(TrustedDevice{UserID: user.ID, DeviceID: input.DeviceID}).
			Assign(TrustedDevice{LastUsedAt: time.Now() /*, Description: if_new_description */}).
			FirstOrCreate(&trustedDevice).Error; err != nil {
			log.Printf("警告: 无法在 TOTP 验证后保存受信任的设备 %s: %v", input.DeviceID, err)
			// Not fatal for login itself, but log it.
		} else {
			log.Printf("设备 %s 已为用户 %s 添加/更新为受信任设备", input.DeviceID, user.Username)
		}
	}

	accessToken, refreshToken, err := generateAccessAndRefreshTokens(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法生成令牌", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// POST /2fa/setup (需要认证)
func SetupTOTPHandler(c *gin.Context) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户未认证"})
		return
	}
	userID := userIDVal.(uuid.UUID)

	var user User
	if err := dbClient.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "找不到用户"})
		return
	}

	if user.IsTOTPEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "TOTP 已启用"})
		return
	}

	secret := generateTOTPSecret()
	err := redisClient.Set(context.Background(), totpTempStorePrefix+userID.String(), secret, time.Minute*10).Err()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法存储临时 TOTP 密钥", "details": err.Error()})
		return
	}

	qrCodeURL, err := generateTOTPQRCode(user.Username, secret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法生成二维码 URL", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "请扫描二维码并验证 TOTP 码",
		"qr_code_url": qrCodeURL, 
		"secret":      secret,    
	})
}

// POST /2fa/verify (需要认证)
type VerifySetupTOTPInput struct {
	Code string `json:"code" binding:"required,len=6"`
}

func VerifyAndEnableTOTPHandler(c *gin.Context) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户未认证"})
		return
	}
	userID := userIDVal.(uuid.UUID)

	var input VerifySetupTOTPInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	secret, err := redisClient.Get(context.Background(), totpTempStorePrefix+userID.String()).Result()
	if err == redis.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "TOTP 设置会话已过期或不存在"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法获取临时 TOTP 密钥", "details": err.Error()})
		return
	}

	if !validateTOTP(secret, input.Code) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的 TOTP 码"})
		return
	}

	if err := dbClient.Model(&User{}).Where("id = ?", userID).Updates(User{
		TOTPSecret:    secret,
		IsTOTPEnabled: true,
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法更新用户信息以启用 TOTP", "details": err.Error()})
		return
	}

	redisClient.Del(context.Background(), totpTempStorePrefix+userID.String())
	c.JSON(http.StatusOK, gin.H{"message": "TOTP 已成功启用"})
}

// POST /2fa/disable (需要认证)
type DisableTOTPInput struct {
	Password string `json:"password,omitempty"` 
	Code     string `json:"code,omitempty"`     
}
func DisableTOTPHandler(c *gin.Context) {
    userIDVal, exists := c.Get("userID")
    if !exists {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "用户未认证"})
        return
    }
    userID := userIDVal.(uuid.UUID)

    var input DisableTOTPInput
    _ = c.ShouldBindJSON(&input) 

    var user User
    if err := dbClient.First(&user, userID).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "找不到用户"})
        return
    }

    if !user.IsTOTPEnabled {
        c.JSON(http.StatusBadRequest, gin.H{"error": "TOTP 尚未启用"})
        return
    }

    if err := dbClient.Model(&user).Updates(User{
        TOTPSecret:    "", 
        IsTOTPEnabled: false,
    }).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "无法禁用 TOTP", "details": err.Error()})
        return
    }

    // Optional: Remove all trusted devices for this user when 2FA is disabled?
    // Or let them persist? Current approach: let them persist.
    // If you want to remove:
    // if err := dbClient.Where("user_id = ?", userID).Delete(&TrustedDevice{}).Error; err != nil {
    //    log.Printf("警告: 禁用 TOTP 后无法移除受信任的设备: %v", err)
    // }

    c.JSON(http.StatusOK, gin.H{"message": "TOTP 已禁用"})
}


// POST /token/refresh
type RefreshTokenInput struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func RefreshTokenHandler(c *gin.Context) {
	var input RefreshTokenInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims, err := validateToken(input.RefreshToken, jwtRefreshSecretKey)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的刷新令牌", "details": err.Error()})
		return
	}

	userIDStr, err := redisClient.Get(context.Background(), refreshTokenPrefix+input.RefreshToken).Result()
	if err == redis.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "刷新令牌不存在或已失效"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法从 Redis 验证刷新令牌", "details": err.Error()})
		return
	}

	if userIDStr != claims.UserID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "刷新令牌与声明的用户不匹配"})
		return
	}
	
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法解析用户ID", "details": err.Error()})
		return
	}

	newAccessToken, err := generateJWT(userID, jwtSecretKey, accessTokenDuration)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法生成新的访问令牌", "details": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"access_token": newAccessToken})
}

// POST /logout
type LogoutInput struct {
	RefreshToken string `json:"refresh_token" binding:"required"` 
}
func LogoutHandler(c *gin.Context) {
	var input LogoutInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "需要 refresh_token", "details": err.Error()})
		return
	}

	deletedCount, err := redisClient.Del(context.Background(), refreshTokenPrefix+input.RefreshToken).Result()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "登出时 Redis 操作失败", "details": err.Error()})
		return
	}

	if deletedCount == 0 {
		c.JSON(http.StatusOK, gin.H{"message": "刷新令牌未找到或已失效，登出成功（客户端应清除本地令牌）"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "登出成功，刷新令牌已作废"})
}


// GET /me (受保护的路由示例)
func MeHandler(c *gin.Context) {
	userIDVal, _ := c.Get("userID")
	userID := userIDVal.(uuid.UUID)

	var user User
	if err := dbClient.Select("id", "username", "email", "is_totp_enabled", "created_at", "updated_at").First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "找不到用户"})
		return
	}
	c.JSON(http.StatusOK, user)
}

// GET /me/devices (New endpoint to list trusted devices)
func ListTrustedDevicesHandler(c *gin.Context) {
    userIDVal, exists := c.Get("userID")
    if !exists {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "用户未认证"})
        return
    }
    userID := userIDVal.(uuid.UUID)

    var devices []TrustedDevice
    if err := dbClient.Where("user_id = ?", userID).Find(&devices).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "无法获取受信任的设备列表", "details": err.Error()})
        return
    }
    c.JSON(http.StatusOK, devices)
}

// DELETE /me/devices/:deviceID (New endpoint to remove a trusted device)
func RemoveTrustedDeviceHandler(c *gin.Context) {
    userIDVal, exists := c.Get("userID")
    if !exists {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "用户未认证"})
        return
    }
    userID := userIDVal.(uuid.UUID)
    deviceIDParam := c.Param("deviceID") // Get deviceID from path parameter

    if deviceIDParam == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "设备 ID 不能为空"})
        return
    }

    // Ensure the user is deleting their own device
    result := dbClient.Where("user_id = ? AND device_id = ?", userID, deviceIDParam).Delete(&TrustedDevice{})
    if result.Error != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "无法移除受信任的设备", "details": result.Error.Error()})
        return
    }
    if result.RowsAffected == 0 {
        c.JSON(http.StatusNotFound, gin.H{"error": "未找到该受信任的设备或权限不足"})
        return
    }

    log.Printf("用户 %s 移除了受信任的设备 %s", userID, deviceIDParam)
    c.JSON(http.StatusOK, gin.H{"message": "受信任的设备已成功移除"})
}


// --- 主函数和路由设置 ---
func main() {
	InitDB()
	InitRedis()

	router := gin.Default()
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"*"} 
	config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization"}
	router.Use(cors.New(config))

	router.POST("/register", RegisterHandler)
	router.POST("/login", LoginHandler)
	router.POST("/login/verify-totp", VerifyTOTPLoginHandler)
	router.POST("/token/refresh", RefreshTokenHandler)

	authorized := router.Group("/")
	authorized.Use(AuthMiddleware())
	{
		authorized.GET("/me", MeHandler)
		authorized.POST("/2fa/setup", SetupTOTPHandler)
		authorized.POST("/2fa/verify", VerifyAndEnableTOTPHandler)
		authorized.POST("/2fa/disable", DisableTOTPHandler)
		authorized.POST("/logout", LogoutHandler)

		authorized.GET("/me/devices", ListTrustedDevicesHandler)           // New route
        authorized.DELETE("/me/devices/:deviceID", RemoveTrustedDeviceHandler) // New route
	}
	
	router.GET("/qr-code", func(c *gin.Context) {
		otpURL := c.Query("url") 
		if otpURL == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 url 参数"})
			return
		}
		key, err := otp.NewKeyFromURL(otpURL)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "无法解析 otpauth URL", "details": err.Error()})
			return
		}
		img, err := key.Image(256, 256)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "无法生成二维码图像", "details": err.Error()})
			return
		}
		c.Writer.Header().Set("Content-Type", "image/png")
		err = png.Encode(c.Writer, img)
		if err != nil {
			log.Printf("无法编码 PNG: %v", err)
		}
	})

	port := getEnv("PORT", "8080")
	log.Printf("服务器正在监听端口 %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("无法启动服务器: %v", err)
	}
}
