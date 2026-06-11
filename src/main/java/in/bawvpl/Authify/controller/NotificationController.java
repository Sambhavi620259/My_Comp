package in.bawvpl.Authify.controller;

import in.bawvpl.Authify.entity.NotificationEntity;
import in.bawvpl.Authify.io.ApiResponse;
import in.bawvpl.Authify.service.NotificationService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.data.domain.Page;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;

import org.springframework.web.bind.annotation.*;

import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@RestController
@RequestMapping("/api/v1.0/notifications")
@RequiredArgsConstructor
@Slf4j
public class NotificationController {

    private final NotificationService notificationService;

    // =====================================================
    // HELPER
    // =====================================================

    private String getEmail(
            Authentication auth
    ) {

        if (

                auth == null ||

                        auth.getName() == null ||

                        auth.getName().isBlank()
        ) {

            throw new ResponseStatusException(

                    HttpStatus.UNAUTHORIZED,

                    "Unauthorized"
            );
        }

        return auth.getName()
                .trim()
                .toLowerCase();
    }

    // =====================================================
    // GET USER NOTIFICATIONS
    // =====================================================

    @GetMapping({"", "/", "/my"})
    public ResponseEntity<ApiResponse<?>> getNotifications(

            Authentication auth,

            @RequestParam(defaultValue = "0")
            int page,

            @RequestParam(defaultValue = "10")
            int size
    ) {

        // =====================================================
        // SAFE PAGINATION
        // =====================================================

        if (page < 0) {

            page = 0;
        }

        if (size <= 0) {

            size = 10;
        }

        if (size > 100) {

            size = 100;
        }

        Page<NotificationEntity> pageData =
                notificationService.getNotifications(

                        getEmail(auth),

                        page,

                        size
                );

        return ResponseEntity.ok(

                ApiResponse.builder()

                        .success(true)

                        .status(200)

                        .message("Notifications fetched successfully")

                        .data(
                                pageData.getContent()
                        )

                        .meta(

                                Map.of(

                                        "page",
                                        pageData.getNumber(),

                                        "size",
                                        pageData.getSize(),

                                        "totalPages",
                                        pageData.getTotalPages(),

                                        "totalElements",
                                        pageData.getTotalElements(),

                                        "hasNext",
                                        pageData.hasNext(),

                                        "hasPrevious",
                                        pageData.hasPrevious(),

                                        "isFirst",
                                        pageData.isFirst(),

                                        "isLast",
                                        pageData.isLast()
                                )
                        )

                        .build()
        );
    }

    // =====================================================
// ADMIN NOTIFICATIONS
// =====================================================

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public ResponseEntity<ApiResponse<?>> getAdminNotifications(

            Authentication auth,

            @RequestParam(defaultValue = "0")
            int page,

            @RequestParam(defaultValue = "20")
            int size
    ) {

        return getNotifications(
                auth,
                page,
                size
        );
    }

    // =====================================================
    // MARK SINGLE NOTIFICATION AS READ
    // =====================================================

    @PatchMapping("/{id}/read")
    public ResponseEntity<ApiResponse<Object>> markAsRead(

            @PathVariable Long id,

            Authentication auth
    ) {

        if (

                id == null ||

                        id <= 0
        ) {

            throw new ResponseStatusException(

                    HttpStatus.BAD_REQUEST,

                    "Invalid notification id"
            );
        }

        notificationService.markAsRead(

                id,

                getEmail(auth)
        );

        log.info(
                "Notification {} marked as read",
                id
        );

        return ResponseEntity.ok(

                ApiResponse.<Object>builder()

                        .success(true)

                        .status(200)

                        .message("Notification marked as read successfully")

                        .data(null)

                        .build()
        );
    }


    @PutMapping("/{id}/read")
    public ResponseEntity<ApiResponse<Object>> markAsReadPut(
            @PathVariable Long id,
            Authentication auth
    ) {
        return markAsRead(id, auth);
    }


    // =====================================================
    // MARK ALL AS READ
    // =====================================================

    @PatchMapping("/read-all")
    public ResponseEntity<ApiResponse<Object>> markAllAsRead(
            Authentication auth
    ) {

        notificationService.markAllAsRead(
                getEmail(auth)
        );

        log.info(
                "All notifications marked as read"
        );

        return ResponseEntity.ok(

                ApiResponse.<Object>builder()

                        .success(true)

                        .status(200)

                        .message("All notifications marked as read successfully")

                        .data(null)

                        .build()
        );
    }

    @PutMapping("/read-all")
    public ResponseEntity<ApiResponse<Object>> markAllAsReadPut(
            Authentication auth
    ) {
        return markAllAsRead(auth);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Object>> deleteNotification(

            @PathVariable Long id,

            Authentication auth
    ) {

        if (
                id == null ||
                        id <= 0
        ) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid notification id"
            );
        }

        notificationService.deleteNotification(
                id,
                getEmail(auth)
        );

        return ResponseEntity.ok(

                ApiResponse.<Object>builder()

                        .success(true)

                        .status(200)

                        .message("Notification deleted successfully")

                        .data(null)

                        .build()
        );
    }

    // =====================================================
    // GET UNREAD COUNT
    // =====================================================

    @GetMapping("/unread-count")
    public ResponseEntity<ApiResponse<Long>> getUnreadCount(
            Authentication auth
    ) {

        long count =
                notificationService
                        .getUnreadCountByEmail(
                                getEmail(auth)
                        );

        return ResponseEntity.ok(

                ApiResponse.<Long>builder()

                        .success(true)

                        .status(200)

                        .message("Unread count fetched successfully")

                        .data(count)

                        .build()
        );
    }

    // =====================================================
    // HEALTH CHECK
    // =====================================================

    @GetMapping("/health")
    public ResponseEntity<ApiResponse<String>> health() {

        return ResponseEntity.ok(

                ApiResponse.<String>builder()

                        .success(true)

                        .status(200)

                        .message("Notification service is running")

                        .data("OK")

                        .build()
        );
    }
}