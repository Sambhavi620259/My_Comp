package in.bawvpl.Authify.service;

import in.bawvpl.Authify.entity.NotificationEntity;
import in.bawvpl.Authify.entity.UserEntity;

import in.bawvpl.Authify.repository.NotificationRepository;
import in.bawvpl.Authify.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import org.springframework.http.HttpStatus;

import org.springframework.stereotype.Service;

import org.springframework.transaction.annotation.Transactional;

import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class NotificationService {

    private final NotificationRepository notificationRepository;

    private final UserRepository userRepository;

    // =====================================================
    // GET NOTIFICATIONS
    // =====================================================

    @Transactional(readOnly = true)
    public Page<NotificationEntity> getNotifications(

            String email,

            int page,

            int size
    ) {

        String normalizedEmail =
                normalizeEmail(email);

        // =====================================================
        // SAFE PAGINATION
        // =====================================================

        if (page < 0) {

            page = 0;
        }

        if (size <= 0 || size > 100) {

            size = 10;
        }

        Pageable pageable =
                PageRequest.of(

                        page,

                        size,

                        Sort.by("createdAt")
                                .descending()
                );

        return notificationRepository
                .findByUser_EmailIgnoreCaseOrderByCreatedAtDesc(

                        normalizedEmail,

                        pageable
                );
    }

    // =====================================================
    // MARK SINGLE AS READ
    // =====================================================

    public void markAsRead(

            Long notificationId,

            String email
    ) {

        String normalizedEmail =
                normalizeEmail(email);

        NotificationEntity notification =
                notificationRepository
                        .findByIdAndUser_EmailIgnoreCase(

                                notificationId,

                                normalizedEmail
                        )

                        .orElseThrow(() ->

                                new ResponseStatusException(

                                        HttpStatus.NOT_FOUND,

                                        "Notification not found"
                                )
                        );

        // =====================================================
        // ALREADY READ
        // =====================================================

        if (Boolean.TRUE.equals(notification.getRead())) {

            return;
        }

        notification.markAsRead();

        notificationRepository.save(notification);

        log.info(
                "Notification {} marked as read for {}",
                notificationId,
                normalizedEmail
        );
    }

    // =====================================================
    // MARK ALL AS READ
    // =====================================================

    public void markAllAsRead(
            String email
    ) {

        String normalizedEmail =
                normalizeEmail(email);

        int updated =
                notificationRepository
                        .markAllAsReadByEmail(
                                normalizedEmail
                        );

        log.info(
                "{} notifications marked as read for {}",
                updated,
                normalizedEmail
        );
    }

    // =====================================================
    // CREATE NOTIFICATION
    // =====================================================

    public void create(

            Long userId,

            String title,

            String message
    ) {

        create(

                userId,

                title,

                message,

                "INFO"
        );
    }

    // =====================================================
    // CREATE WITH TYPE
    // =====================================================

    public void create(

            Long userId,

            String title,

            String message,

            String type
    ) {

        if (

                title == null ||

                        title.isBlank()
        ) {

            throw new ResponseStatusException(

                    HttpStatus.BAD_REQUEST,

                    "Title required"
            );
        }

        if (

                message == null ||

                        message.isBlank()
        ) {

            throw new ResponseStatusException(

                    HttpStatus.BAD_REQUEST,

                    "Message required"
            );
        }

        UserEntity user =
                userRepository
                        .findById(userId)
                        .orElseThrow(() ->

                                new ResponseStatusException(

                                        HttpStatus.NOT_FOUND,

                                        "User not found"
                                )
                        );

        NotificationEntity notification =
                NotificationEntity.builder()

                        .user(user)

                        .title(
                                title.trim()
                        )

                        .message(
                                message.trim()
                        )

                        .read(false)

                        .createdAt(
                                LocalDateTime.now()
                        )

                        .type(

                                type != null &&

                                        !type.isBlank()

                                        ? type.trim()
                                        .toUpperCase()
                                        .replace(" ", "_")

                                        : "INFO"
                        )

                        .build();

        notificationRepository.save(notification);

        log.info(
                "Notification created for user {}",
                userId
        );
    }

    // =====================================================
// ADMIN BROADCAST
// =====================================================

    public void notifyAdmins(

            String title,

            String message,

            String type
    ) {

        userRepository.findAll()

                .stream()

                .filter(user ->

                        user.getRole() != null &&

                                (

                                        user.getRole().equalsIgnoreCase("ROLE_ADMIN") ||

                                                user.getRole().equalsIgnoreCase("ADMIN")
                                )
                )

                .forEach(admin ->

                        create(

                                admin.getId(),

                                title,

                                message,

                                type
                        )
                );
    }

    // =====================================================
    // UNREAD COUNT
    // =====================================================

    @Transactional(readOnly = true)
    public long getUnreadCountByEmail(
            String email
    ) {

        String normalizedEmail =
                normalizeEmail(email);

        return notificationRepository
                .countByUser_EmailIgnoreCaseAndReadFalse(
                        normalizedEmail
                );
    }

    public void deleteNotification(
            Long notificationId,
            String email
    ) {

        String normalizedEmail =
                normalizeEmail(email);

        NotificationEntity notification =
                notificationRepository
                        .findByIdAndUser_EmailIgnoreCase(
                                notificationId,
                                normalizedEmail
                        )
                        .orElseThrow(() ->

                                new ResponseStatusException(
                                        HttpStatus.NOT_FOUND,
                                        "Notification not found"
                                )
                        );

        notificationRepository.delete(notification);

        log.info(
                "Notification {} deleted for {}",
                notificationId,
                normalizedEmail
        );
    }

    // =====================================================
    // NORMALIZE EMAIL
    // =====================================================

    private String normalizeEmail(
            String email
    ) {

        if (

                email == null ||

                        email.isBlank()
        ) {

            throw new ResponseStatusException(

                    HttpStatus.BAD_REQUEST,

                    "Email required"
            );
        }

        return email
                .trim()
                .toLowerCase();
    }
}