package in.bawvpl.Authify.service;

import in.bawvpl.Authify.entity.OtpVerification;
import in.bawvpl.Authify.entity.UserEntity;

import in.bawvpl.Authify.repository.OtpRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.HttpStatus;

import org.springframework.stereotype.Service;

import org.springframework.transaction.annotation.Transactional;

import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;

import java.util.concurrent.ThreadLocalRandom;

@Service
@RequiredArgsConstructor
@Slf4j
public class OtpServiceImpl implements OtpService {

    private final OtpRepository otpRepository;

    private final EmailService emailService;

    private final SmsService smsService;

    private static final int EXPIRY_MINUTES = 5;

    private static final int MAX_ATTEMPTS = 5;

    private static final int COOLDOWN_SECONDS = 30;

    // =====================================================
    // GENERATE RANDOM OTP
    // =====================================================

    @Override
    public String generateOtp() {

        return String.valueOf(

                ThreadLocalRandom.current()
                        .nextInt(100000, 999999)
        );
    }

    // =====================================================
    // LOGIN
    // =====================================================

    @Override
    @Transactional
    public String generateLoginOtp(
            UserEntity user
    ) {

        return generate(
                user,
                "LOGIN"
        );
    }

    @Override
    @Transactional
    public void verifyLoginOtp(

            UserEntity user,

            String otp
    ) {

        validate(
                user,
                otp,
                "LOGIN"
        );
    }

    // =====================================================
    // REGISTER
    // =====================================================

    @Override
    @Transactional
    public String generateRegisterOtp(
            UserEntity user
    ) {

        return generate(
                user,
                "REGISTER"
        );
    }

    @Override
    @Transactional
    public void verifyRegisterOtp(

            UserEntity user,

            String otp
    ) {

        validate(
                user,
                otp,
                "REGISTER"
        );
    }

    // =====================================================
    // RESET PASSWORD
    // =====================================================

    @Override
    @Transactional
    public String generateResetOtp(
            UserEntity user
    ) {

        return generate(
                user,
                "RESET_PASSWORD"
        );
    }

    @Override
    @Transactional
    public void verifyResetOtp(

            UserEntity user,

            String otp
    ) {

        validate(
                user,
                otp,
                "RESET_PASSWORD"
        );
    }

    // =====================================================
    // PHONE OTP
    // =====================================================

    @Override
    @Transactional
    public String generatePhoneOtp(
            UserEntity user
    ) {

        return generate(
                user,
                "PHONE"
        );
    }

    @Override
    @Transactional
    public void verifyPhoneOtp(

            UserEntity user,

            String otp
    ) {

        validate(
                user,
                otp,
                "PHONE"
        );
    }

    // =====================================================
    // COMMON OTP GENERATOR
    // =====================================================

    private String generate(

            UserEntity user,

            String purpose
    ) {

        if (user == null) {

            throw new ResponseStatusException(

                    HttpStatus.BAD_REQUEST,

                    "User required"
            );
        }

        String email =
                normalize(
                        user.getEmail()
                );

        String phone =
                user.getPhoneNumber();

        // =====================================================
        // COOLDOWN
        // =====================================================

        OtpVerification last =

                otpRepository
                        .findTopByEmailAndPurposeOrderByCreatedAtDesc(

                                email,

                                purpose
                        )
                        .orElse(null);

        if (

                last != null &&

                        last.getLastSentAt() != null &&

                        last.getLastSentAt()
                                .plusSeconds(COOLDOWN_SECONDS)
                                .isAfter(LocalDateTime.now())
        ) {

            throw new ResponseStatusException(

                    HttpStatus.TOO_MANY_REQUESTS,

                    "Wait before requesting OTP again"
            );
        }

        String otp =
                generateOtp();

        // =====================================================
        // INVALIDATE OLD OTP
        // =====================================================

        invalidateOldOtp(
                email,
                purpose
        );

        OtpVerification entity =
                new OtpVerification();

        entity.setUserId(
                user.getId()
        );

        entity.setEmail(email);

        entity.setPhoneNumber(phone);

        entity.setOtp(otp);

        entity.setPurpose(purpose);

        entity.setExpiryTime(

                LocalDateTime.now()
                        .plusMinutes(EXPIRY_MINUTES)
        );

        entity.setIsUsed(false);

        entity.setAttempts(0);

        entity.setLastSentAt(
                LocalDateTime.now()
        );

        otpRepository.save(entity);

        // =====================================================
        // EMAIL DELIVERY
        // =====================================================

        if (

                email == null ||

                        email.isBlank()
        ) {

            throw new ResponseStatusException(

                    HttpStatus.BAD_REQUEST,

                    "Email required for OTP"
            );
        }

        try {

            if ("LOGIN".equals(purpose)) {

                emailService.sendLoginOtpEmail(
                        email,
                        otp
                );

            } else if ("RESET_PASSWORD".equals(purpose)) {

                emailService.sendResetOtpEmail(
                        email,
                        otp
                );

            } else {

                emailService.sendVerificationOtpEmail(
                        email,
                        otp
                );
            }

            log.info(
                    "📧 OTP sent to email {}",
                    email
            );

        } catch (Exception e) {

            log.error(
                    "❌ Email OTP failed",
                    e
            );

            throw new ResponseStatusException(

                    HttpStatus.INTERNAL_SERVER_ERROR,

                    "Failed to send OTP email"
            );
        }

        // =====================================================
        // SMS DELIVERY (OPTIONAL)
        // =====================================================

        if (

                phone != null &&

                        !phone.isBlank()
        ) {

            try {

                smsService.sendVerificationOtp(
                        phone,
                        otp
                );

                log.info(
                        "📱 OTP sent to phone {}",
                        phone
                );

            } catch (Exception e) {

                log.warn(
                        "⚠️ SMS failed: {}",
                        e.getMessage()
                );
            }
        }

        log.info(
                "✅ {} OTP generated for {}",
                purpose,
                email
        );

        return otp;
    }

    // =====================================================
    // VALIDATE OTP
    // =====================================================

    private void validate(

            UserEntity user,

            String otp,

            String purpose
    ) {

        if (

                user == null
        ) {

            throw new ResponseStatusException(

                    HttpStatus.BAD_REQUEST,

                    "User required"
            );
        }

        if (

                otp == null ||

                        otp.isBlank()
        ) {

            throw new ResponseStatusException(

                    HttpStatus.BAD_REQUEST,

                    "OTP required"
            );
        }

        String email =
                normalize(
                        user.getEmail()
                );

        OtpVerification entity =

                otpRepository
                        .findTopByEmailAndPurposeOrderByCreatedAtDesc(

                                email,

                                purpose
                        )
                        .orElseThrow(() ->

                                new ResponseStatusException(

                                        HttpStatus.BAD_REQUEST,

                                        "OTP not found"
                                )
                        );

        // =====================================================
        // MAX ATTEMPTS
        // =====================================================

        if (

                entity.getAttempts() != null &&

                        entity.getAttempts() >= MAX_ATTEMPTS
        ) {

            throw new ResponseStatusException(

                    HttpStatus.TOO_MANY_REQUESTS,

                    "Too many attempts"
            );
        }

        entity.setAttempts(

                entity.getAttempts() == null

                        ? 1

                        : entity.getAttempts() + 1
        );

        if (

                Boolean.TRUE.equals(
                        entity.getIsUsed()
                )
        ) {

            throw new ResponseStatusException(

                    HttpStatus.BAD_REQUEST,

                    "OTP already used"
            );
        }

        if (

                !entity.getOtp()
                        .equals(otp)
        ) {

            otpRepository.save(entity);

            throw new ResponseStatusException(

                    HttpStatus.BAD_REQUEST,

                    "Invalid OTP"
            );
        }

        if (

                entity.getExpiryTime() == null ||

                        entity.getExpiryTime()
                                .isBefore(LocalDateTime.now())
        ) {

            throw new ResponseStatusException(

                    HttpStatus.BAD_REQUEST,

                    "OTP expired"
            );
        }

        entity.setIsUsed(true);

        otpRepository.save(entity);

        log.info(
                "✅ {} OTP verified for {}",
                purpose,
                email
        );
    }

    // =====================================================
    // INVALIDATE OLD OTP
    // =====================================================

    private void invalidateOldOtp(

            String email,

            String purpose
    ) {

        otpRepository
                .findTopByEmailAndPurposeOrderByCreatedAtDesc(

                        email,

                        purpose
                )
                .ifPresent(old -> {

                    old.setIsUsed(true);

                    otpRepository.save(old);
                });
    }

    // =====================================================
    // NORMALIZE EMAIL
    // =====================================================

    private String normalize(
            String email
    ) {

        return email == null

                ? ""

                : email.trim()
                .toLowerCase();
    }
}