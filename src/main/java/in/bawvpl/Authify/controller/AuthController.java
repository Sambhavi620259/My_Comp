package in.bawvpl.Authify.controller;

import in.bawvpl.Authify.entity.KycEntity;
import in.bawvpl.Authify.entity.UserEntity;
import in.bawvpl.Authify.entity.UserStatus;

import in.bawvpl.Authify.io.*;

import in.bawvpl.Authify.repository.KycRepository;
import in.bawvpl.Authify.repository.UserRepository;

import in.bawvpl.Authify.service.*;

import in.bawvpl.Authify.util.JwtUtil;

import jakarta.validation.Valid;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import in.bawvpl.Authify.io.ForgotPasswordRequest;
import in.bawvpl.Authify.io.ResetPasswordRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
@Slf4j
//@CrossOrigin("*")
@RequestMapping("/api/v1.0")
public class AuthController {

    private final UserRepository userRepository;

    private final KycRepository kycRepository;

    private final ProfileService profileService;

    private final OtpService otpService;

    private final PasswordEncoder passwordEncoder;

    //private final StorageService storageService;

    private final S3Service s3Service;

    private final JwtUtil jwtUtil;
    private final ActivityService activityService;

    private final NotificationService notificationService;

    // =====================================================
    // BASE URL
    // =====================================================

    private static final String BASE_URL =
            "http://43.205.116.38:8080";

    // =====================================================
    // REGISTER
    // =====================================================

    @PostMapping(
            value = "/register",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE
    )
    public ResponseEntity<?> register(

            @ModelAttribute RegisterRequest request,

            @RequestParam(
                    value = "file",
                    required = false
            )
            MultipartFile file
    ) {

        try {

            // =====================================================
            // VALIDATION
            // =====================================================

            if (

                    request.getEmail() == null ||

                            request.getEmail().isBlank()
            ) {

                return badRequest(
                        "Email required"
                );
            }

            if (

                    request.getPassword() == null ||

                            request.getPassword().isBlank()
            ) {

                return badRequest(
                        "Password required"
                );
            }

            if (

                    request.getName() == null ||

                            request.getName().isBlank()
            ) {

                return badRequest(
                        "Name required"
                );
            }

            String email =
                    request.getEmail()
                            .trim()
                            .toLowerCase();

            // =====================================================
            // EMAIL EXISTS
            // =====================================================

            if (
                    userRepository.existsByEmailIgnoreCase(email)
            ) {

                return ResponseEntity
                        .status(HttpStatus.CONFLICT)
                        .body(
                                Map.of(

                                        "success", false,

                                        "message",
                                        "Email already registered"
                                )
                        );
            }

            // =====================================================
            // FILE UPLOAD
            // =====================================================

            String uploadedFileUrl = null;

            if (

                    file != null &&

                            !file.isEmpty()
            ) {

                uploadedFileUrl =
                        s3Service.uploadFile(file);

                uploadedFileUrl =
                        normalizeUrl(uploadedFileUrl);

                log.info(
                        "Document uploaded : {}",
                        uploadedFileUrl
                );
            }

            // =====================================================
            // PROFILE REQUEST
            // =====================================================

            ProfileRequest profileRequest =
                    ProfileRequest.builder()

                            .name(
                                    request.getName()
                            )

                            .email(email)

                            .phoneNumber(
                                    request.getPhoneNumber()
                            )

                            .password(
                                    request.getPassword()
                            )

                            .address(
                                    request.getAddress()
                            )

                            .referralCode(
                                    request.getReferralCode()
                            )

                            .documentType(
                                    request.getDocumentType()
                            )

                            .documentNumber(
                                    request.getDocumentNumber()
                            )

                            .filePath(
                                    uploadedFileUrl
                            )

                            .build();

            // =====================================================
            // CREATE PROFILE
            // =====================================================

            profileService.createProfile(
                    profileRequest
            );

            log.info(
                    "Registration successful for {}",
                    email
            );

            return ResponseEntity.ok(

                    Map.of(

                            "success", true,

                            "message",
                            "Registration successful. Verification email sent.",

                            "documentUploaded",
                            uploadedFileUrl != null,

                            "filePath",
                            uploadedFileUrl
                    )
            );

        } catch (ResponseStatusException e) {

            return ResponseEntity
                    .status(e.getStatusCode())
                    .body(
                            Map.of(

                                    "success", false,

                                    "message",
                                    e.getReason()
                            )
                    );

        } catch (Exception e) {

            log.error(
                    "Registration failed",
                    e
            );

            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(
                            Map.of(

                                    "success", false,

                                    "message",
                                    "Registration failed",

                                    "error",
                                    e.getMessage()
                            )
                    );
        }
    }

    // =====================================================
    // VERIFY EMAIL
    // =====================================================

    @GetMapping(
            value = "/verify-email",
            produces = MediaType.TEXT_HTML_VALUE
    )
    public ResponseEntity<String> verifyEmail(
            @RequestParam String token
    ) {

        try {

            profileService.verifyEmailToken(
                    token
            );

            return ResponseEntity.ok("""

                    <!DOCTYPE html>

                    <html>

                    <head>

                        <title>Email Verified</title>

                        <style>

                            body {

                                font-family: Arial, sans-serif;
                                background: #f5f5f5;
                                text-align: center;
                                padding-top: 100px;
                            }

                            .card {

                                background: white;
                                width: 420px;
                                margin: auto;
                                padding: 40px;
                                border-radius: 10px;
                                box-shadow: 0 0 10px rgba(0,0,0,0.1);
                            }

                            h1 {

                                color: green;
                            }

                            a {

                                display: inline-block;
                                margin-top: 20px;
                                padding: 12px 20px;
                                background: #1976d2;
                                color: white;
                                text-decoration: none;
                                border-radius: 6px;
                            }

                        </style>

                    </head>

                    <body>

                        <div class="card">

                            <h1>
                                Registration Successful
                            </h1>

                            <p>
                                Your email has been verified successfully.
                            </p>

                            <a href="http://43.205.116.38:5173/login">
                                Go Back To Login
                            </a>

                        </div>

                    </body>

                    </html>

                    """);

        } catch (ResponseStatusException e) {

            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("""

                            <html>

                            <body style='font-family:Arial;text-align:center;padding-top:100px'>

                            <h1 style='color:red'>
                                Verification Failed
                            </h1>

                            <p>
                            """ + e.getReason() + """
                            </p>

                            </body>

                            </html>

                            """);

        } catch (Exception e) {

            log.error(
                    "Email verification failed",
                    e
            );

            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("""

                            <html>

                            <body style='font-family:Arial;text-align:center;padding-top:100px'>

                            <h1 style='color:red'>
                                Internal Server Error
                            </h1>

                            </body>

                            </html>

                            """);
        }
    }

    // =====================================================
    // LOGIN
    // =====================================================

    @PostMapping("/login")
    public ResponseEntity<?> login(

            @Valid
            @RequestBody LoginRequest request
    ) {

        try {

            if (

                    request.getEmail() == null ||

                            request.getEmail().isBlank()
            ) {

                return badRequest(
                        "Email required"
                );
            }

            if (

                    request.getPassword() == null ||

                            request.getPassword().isBlank()
            ) {

                return badRequest(
                        "Password required"
                );
            }

            String email =
                    request.getEmail()
                            .trim()
                            .toLowerCase();

            UserEntity user =
                    userRepository
                            .findByEmailIgnoreCase(email)

                            .orElseThrow(() ->

                                    new ResponseStatusException(

                                            HttpStatus.NOT_FOUND,

                                            "User not found"
                                    )
                            );

            // =====================================================
            // PASSWORD CHECK
            // =====================================================

            if (
                    !passwordEncoder.matches(

                            request.getPassword(),

                            user.getPassword()
                    )
            ) {

                return ResponseEntity
                        .status(HttpStatus.UNAUTHORIZED)
                        .body(
                                Map.of(

                                        "success", false,

                                        "message",
                                        "Invalid credentials"
                                )
                        );
            }

            // =====================================================
            // EMAIL VERIFIED
            // =====================================================

            if (
                    !Boolean.TRUE.equals(
                            user.getEmailVerified()
                    )
            ) {

                return ResponseEntity
                        .status(HttpStatus.FORBIDDEN)
                        .body(
                                Map.of(

                                        "success", false,

                                        "message",
                                        "Please verify your email first"
                                )
                        );
            }

            // =====================================================
            // ACCOUNT STATUS
            // =====================================================

            if (

                    user.getUserStatus() == UserStatus.BLOCKED ||

                            user.getUserStatus() == UserStatus.SUSPENDED ||

                            user.getUserStatus() == UserStatus.DELETED
            ) {

                return ResponseEntity
                        .status(HttpStatus.FORBIDDEN)
                        .body(
                                Map.of(

                                        "success", false,

                                        "message",
                                        "Account restricted"
                                )
                        );
            }

            // =====================================================
            // GENERATE OTP
            // =====================================================

            otpService.generateLoginOtp(user);

            return ResponseEntity.ok(
                    Map.of(

                            "success", true,

                            "message",
                            "OTP sent successfully"
                    )
            );

        } catch (ResponseStatusException e) {

            return ResponseEntity
                    .status(e.getStatusCode())
                    .body(
                            Map.of(

                                    "success", false,

                                    "message",
                                    e.getReason()
                            )
                    );

        } catch (Exception e) {

            log.error(
                    "Login failed",
                    e
            );

            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(
                            Map.of(

                                    "success", false,

                                    "message",
                                    "Login failed",

                                    "error",
                                    e.getMessage()
                            )
                    );
        }
    }

// =====================================================
// VERIFY OTP
// =====================================================

    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(

            @Valid
            @RequestBody VerifyOtpRequest request
    ) {

        try {

            String email =
                    request.getEmail()
                            .trim()
                            .toLowerCase();

            UserEntity user =
                    userRepository
                            .findByEmailIgnoreCase(email)

                            .orElseThrow(() ->

                                    new ResponseStatusException(

                                            HttpStatus.NOT_FOUND,

                                            "User not found"
                                    )
                            );

            // =====================================================
            // VERIFY OTP
            // =====================================================

            otpService.verifyLoginOtp(

                    user,

                    request.getOtp()
            );



            // =====================================================
            // SAVE LOGIN ACTIVITY
            // =====================================================

            activityService.log(

                    user.getEmail(),

                    "login",

                    "User logged into account"
            );

            // =====================================================
            // ADMIN LOGIN NOTIFICATION
            // =====================================================

            userRepository.findAll()

                    .stream()

                    .filter(u ->

                            u.getRole() != null &&

                                    (
                                            u.getRole().equalsIgnoreCase("ROLE_ADMIN") ||

                                                    u.getRole().equalsIgnoreCase("ADMIN")
                                    )
                    )

                    .forEach(admin ->

                            notificationService.create(

                                    admin.getId(),

                                    "User Login",

                                    user.getEmail() + " logged in",

                                    "ADMIN"
                            )
                    );




            // =====================================================
            // ROLE
            // =====================================================

            String role = "ROLE_USER";

            if (

                    user.getRole() != null &&

                            !user.getRole().isBlank()
            ) {

                role = user.getRole();
            }

            // =====================================================
            // JWT TOKEN
            // =====================================================

            String token =
                    jwtUtil.generateAccessToken(

                            user.getEmail(),

                            user.getTokenVersion(),

                            role
                    );

            String refreshToken =
                    jwtUtil.generateRefreshToken(
                            user.getEmail()
                    );

            // =====================================
            // SAVE REFRESH TOKEN
            // =====================================

            user.setRefreshToken(
                    refreshToken
            );

            userRepository.save(
                    user
            );

            // =====================================================
            // KYC
            // =====================================================

            Optional<KycEntity> optionalKyc =
                    kycRepository.findByUser_Id(
                            user.getId()
                    );

            String documentType = null;

            String documentNumber = null;

            String documentFile = null;

            String kycStatus = "PENDING";

            if (
                    optionalKyc.isPresent()
            ) {

                KycEntity kyc =
                        optionalKyc.get();

                documentType =
                        kyc.getDocumentType();

                documentNumber =
                        kyc.getDocumentNumber();

                documentFile =
                        normalizeUrl(
                                kyc.getFilePath()
                        );

                if (
                        kyc.getStatus() != null
                ) {

                    kycStatus =
                            kyc.getStatus().name();
                }
            }

            // =====================================================
            // RESPONSE
            // =====================================================

            Map<String, Object> response =
                    new HashMap<>();

            response.put(
                    "success",
                    true
            );

            response.put(
                    "message",
                    "Login successful"
            );

            response.put(
                    "token",
                    token
            );

            response.put(
                    "accessToken",
                    token
            );

            response.put(
                    "refreshToken",
                    refreshToken
            );

            response.put(
                    "tokenType",
                    "Bearer"
            );

            response.put(
                    "email",
                    user.getEmail()
            );

            response.put(
                    "userId",
                    user.getUserId()
            );

            response.put(
                    "name",
                    user.getEntityName()
            );

            response.put(
                    "phoneNumber",
                    user.getPhoneNumber()
            );

            response.put(
                    "role",
                    role
            );

            response.put(
                    "emailVerified",
                    Boolean.TRUE.equals(
                            user.getEmailVerified()
                    )
            );

            response.put(
                    "kycVerified",
                    Boolean.TRUE.equals(
                            user.getIsKycVerified()
                    )
            );

            response.put(
                    "kycStatus",
                    kycStatus
            );

            response.put(
                    "userStatus",
                    user.getUserStatus()
            );

            response.put(
                    "documentType",
                    documentType
            );

            response.put(
                    "documentNumber",
                    documentNumber
            );

            response.put(
                    "documentFile",
                    documentFile
            );

            return ResponseEntity.ok(response);

        } catch (ResponseStatusException e) {

            return ResponseEntity
                    .status(e.getStatusCode())
                    .body(
                            Map.of(

                                    "success", false,

                                    "message",
                                    e.getReason()
                            )
                    );

        } catch (Exception e) {

            log.error(
                    "OTP verification failed",
                    e
            );

            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(
                            Map.of(

                                    "success", false,

                                    "message",
                                    "OTP verification failed",

                                    "error",
                                    e.getMessage()
                            )
                    );
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(
            @RequestBody RefreshTokenRequest request
    ) {

        try {

            String refreshToken =
                    request.getRefreshToken();

            if (
                    refreshToken == null ||
                            refreshToken.isBlank()
            ) {

                return badRequest(
                        "Refresh token required"
                );
            }

            if (
                    !jwtUtil.validateToken(
                            refreshToken
                    )
            ) {

                return ResponseEntity
                        .status(HttpStatus.UNAUTHORIZED)
                        .body(
                                Map.of(
                                        "success", false,
                                        "message",
                                        "Invalid refresh token"
                                )
                        );
            }

            String email =
                    jwtUtil.extractUsername(
                            refreshToken
                    );

            UserEntity user =
                    userRepository
                            .findByEmailIgnoreCase(email)
                            .orElseThrow(
                                    () ->
                                            new ResponseStatusException(
                                                    HttpStatus.NOT_FOUND,
                                                    "User not found"
                                            )
                            );

            // =====================================
            // CHECK STORED TOKEN
            // =====================================

            if (
                    user.getRefreshToken() == null ||
                            !refreshToken.equals(
                                    user.getRefreshToken()
                            )
            ) {

                return ResponseEntity
                        .status(HttpStatus.UNAUTHORIZED)
                        .body(
                                Map.of(
                                        "success", false,
                                        "message",
                                        "Refresh token revoked"
                                )
                        );
            }

            String role = "ROLE_USER";

            if (
                    user.getRole() != null &&
                            !user.getRole().isBlank()
            ) {
                role = user.getRole();
            }

            String newAccessToken =
                    jwtUtil.generateAccessToken(
                            user.getEmail(),
                            user.getTokenVersion(),
                            role
                    );

            String newRefreshToken =
                    jwtUtil.generateRefreshToken(
                            user.getEmail()
                    );

            // =====================================
            // ROTATION
            // =====================================

            user.setRefreshToken(
                    newRefreshToken
            );

            userRepository.save(
                    user
            );

            return ResponseEntity.ok(

                    Map.of(

                            "success", true,

                            "accessToken",
                            newAccessToken,

                            "refreshToken",
                            newRefreshToken,

                            "tokenType",
                            "Bearer"
                    )
            );

        } catch (Exception e) {

            log.error(
                    "Refresh token failed",
                    e
            );

            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(
                            Map.of(
                                    "success", false,
                                    "message",
                                    "Refresh failed"
                            )
                    );
        }
    }

    // =====================================================
    // HELPERS
    // =====================================================

    private ResponseEntity<?> badRequest(
            String message
    ) {

        return ResponseEntity
                .badRequest()
                .body(
                        Map.of(

                                "success", false,

                                "message",
                                message
                        )
                );
    }

    private String normalizeUrl(
            String value
    ) {

        if (

                value == null ||

                        value.isBlank()
        ) {

            return null;
        }

        value = value.trim();

        if (

                value.startsWith("http://") ||

                        value.startsWith("https://")
        ) {

            return value;
        }

        if (!value.startsWith("/")) {

            value = "/" + value;
        }

        return BASE_URL + value;
    }

    // =====================================================
    // FORGOT PASSWORD
    // =====================================================

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(
            @Valid
            @RequestBody ForgotPasswordRequest request
    ) {

        try {

            UserEntity user =
                    userRepository
                            .findByEmailIgnoreCase(
                                    request.getEmail()
                                            .trim()
                                            .toLowerCase()
                            )
                            .orElseThrow(() ->

                                    new ResponseStatusException(
                                            HttpStatus.NOT_FOUND,
                                            "User not found"
                                    )
                            );

            otpService.generateResetOtp(user);

            return ResponseEntity.ok(
                    Map.of(
                            "success", true,
                            "message", "Reset OTP sent successfully"
                    )
            );

        } catch (ResponseStatusException e) {

            return ResponseEntity
                    .status(e.getStatusCode())
                    .body(
                            Map.of(
                                    "success", false,
                                    "message", e.getReason()
                            )
                    );
        }
    }

    // =====================================================
    // RESET PASSWORD
    // =====================================================

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(
            @Valid
            @RequestBody ResetPasswordRequest request
    ) {

        try {

            UserEntity user =
                    userRepository
                            .findByEmailIgnoreCase(
                                    request.getEmail()
                                            .trim()
                                            .toLowerCase()
                            )
                            .orElseThrow(() ->

                                    new ResponseStatusException(
                                            HttpStatus.NOT_FOUND,
                                            "User not found"
                                    )
                            );

            otpService.verifyResetOtp(
                    user,
                    request.getOtp()
            );

            user.setPassword(
                    passwordEncoder.encode(
                            request.getNewPassword()
                    )
            );

            user.incrementTokenVersion();
            user.setRefreshToken(null);
            userRepository.save(user);

            return ResponseEntity.ok(
                    Map.of(
                            "success", true,
                            "message", "Password reset successful"
                    )
            );

        } catch (ResponseStatusException e) {

            return ResponseEntity
                    .status(e.getStatusCode())
                    .body(
                            Map.of(
                                    "success", false,
                                    "message", e.getReason()
                            )
                    );
        }
    }

    // =====================================================
    // DTO
    // =====================================================

    @Data
    public static class LoginRequest {

        private String email;

        private String password;
    }


}