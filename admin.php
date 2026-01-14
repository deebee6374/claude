<?php
require_once 'config.php';
require_once 'includes/ContentModerator.php';
require_once 'printify-config.php';
require_once 'object-storage.php';

function getBackgroundImageUrl($path) {
    if (empty($path)) return '';
    if (strpos($path, '/objects/') === 0) {
        try {
            return getObjectDownloadURL($path, 3600);
        } catch (Exception $e) {
            error_log('Failed to get signed URL: ' . $e->getMessage());
            return '';
        }
    }
    return $path;
}

// Check if user is logged in and is admin
if (!isLoggedIn()) {
    header('Location: login.php?redirect=admin.php');
    exit;
}

$user = getCurrentUser();
if (!$user || !$user['is_admin']) {
    header('Location: home.php');
    exit;
}

$pdo = getDBConnection();
$moderator = new ContentModerator($pdo);

// Get last sync time
$lastSyncTime = null;
try {
    $syncStmt = $pdo->prepare("SELECT setting_value FROM site_settings WHERE setting_key = 'printify_last_sync'");
    $syncStmt->execute();
    $syncResult = $syncStmt->fetch();
    if ($syncResult) {
        $lastSyncTime = $syncResult['setting_value'];
    }
} catch (Exception $e) {
    // Table may not exist yet
}

// Generate CSRF token for forms
$csrfToken = generateCSRFToken();

// Handle actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verify CSRF token for all POST requests
    if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
        header('Location: admin.php?error=csrf');
        exit;
    }
    
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'add_word':
                $word = trim($_POST['word'] ?? '');
                $severity = $_POST['severity'] ?? 'medium';
                if (!empty($word)) {
                    $moderator->addBannedWord($word, $severity, $user['id']);
                    header('Location: admin.php?tab=words&success=1');
                    exit;
                }
                break;

            case 'remove_word':
                $wordId = $_POST['word_id'] ?? 0;
                if ($wordId) {
                    $moderator->removeBannedWord($wordId);
                    header('Location: admin.php?tab=words&deleted=1');
                    exit;
                }
                break;

            case 'review_content':
                $flaggedId = $_POST['flagged_id'] ?? 0;
                $status = $_POST['status'] ?? '';
                $notes = $_POST['notes'] ?? '';
                if ($flaggedId && in_array($status, ['approved', 'rejected'])) {
                    $moderator->reviewContent($flaggedId, $status, $user['id'], $notes);
                    header('Location: admin.php?tab=reviews&reviewed=1');
                    exit;
                }
                break;

            case 'update_user_role':
                $userId = intval($_POST['user_id'] ?? 0);
                $role = $_POST['role'] ?? '';
                $value = isset($_POST['value']) && $_POST['value'] === '1';
                if ($userId && in_array($role, ['is_admin', 'is_founder', 'is_active', 'email_verified'])) {
                    $boolValue = $value ? 'true' : 'false';
                    $stmt = $pdo->prepare("UPDATE users SET $role = $boolValue WHERE id = ?");
                    $stmt->execute([$userId]);
                    header('Location: admin.php?tab=users&updated=1');
                    exit;
                }
                break;

            case 'reset_password':
                $userId = intval($_POST['user_id'] ?? 0);
                $newPassword = $_POST['new_password'] ?? '';
                if ($userId && strlen($newPassword) >= 8) {
                    $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
                    $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
                    $stmt->execute([$hashedPassword, $userId]);
                    header('Location: admin.php?tab=users&password_reset=1');
                    exit;
                } else {
                    header('Location: admin.php?tab=users&password_error=1');
                    exit;
                }
                break;

            case 'sync_printify':
                $result = syncPrintifyProducts();
                if ($result['success'] ?? false) {
                    updateSyncTimestamp($pdo);
                    header('Location: admin.php?tab=products&synced=' . ($result['synced'] ?? 0));
                } else {
                    $errorMsg = urlencode($result['error'] ?? 'Unknown error');
                    header('Location: admin.php?tab=products&sync_error=1&error_msg=' . $errorMsg);
                }
                exit;
                
            case 'clear_stuck_publishing':
                $result = clearStuckPublishing();
                if ($result['success'] ?? false) {
                    $cleared = $result['cleared'] ?? 0;
                    $total = $result['total'] ?? 0;
                    header('Location: admin.php?tab=products&cleared=' . $cleared . '&total=' . $total);
                } else {
                    $errorMsg = urlencode($result['error'] ?? 'Unknown error');
                    header('Location: admin.php?tab=products&clear_error=1&error_msg=' . $errorMsg);
                }
                exit;
                
            case 'mark_published':
                $result = markProductsAsPublished();
                if ($result['success'] ?? false) {
                    $published = $result['published'] ?? 0;
                    $skipped = $result['skipped'] ?? 0;
                    $total = $result['total'] ?? 0;
                    header('Location: admin.php?tab=products&published=' . $published . '&skipped=' . $skipped . '&total=' . $total);
                } else {
                    $errorMsg = urlencode($result['error'] ?? 'Unknown error');
                    header('Location: admin.php?tab=products&publish_error=1&error_msg=' . $errorMsg);
                }
                exit;
                
            case 'unlock_rate_limit':
                $userId = intval($_POST['user_id'] ?? 0);
                $limitType = $_POST['limit_type'] ?? '';
                if ($userId && in_array($limitType, ['friend_request', 'post', 'all'])) {
                    if ($limitType === 'all') {
                        $stmt = $pdo->prepare("DELETE FROM rate_limits WHERE user_id = ?");
                        $stmt->execute([$userId]);
                    } else {
                        $stmt = $pdo->prepare("DELETE FROM rate_limits WHERE user_id = ? AND action_type = ?");
                        $stmt->execute([$userId, $limitType]);
                    }
                    header('Location: admin.php?tab=users&unlocked=1');
                    exit;
                }
                break;
                
            case 'delete_user':
                $userId = intval($_POST['user_id'] ?? 0);
                if ($userId && $userId !== $user['id']) {
                    // Get user data first
                    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
                    $stmt->execute([$userId]);
                    $targetUser = $stmt->fetch();
                    
                    if ($targetUser) {
                        // Archive user data to deleted_users table
                        try {
                            $profileData = json_encode([
                                'bio' => $targetUser['bio'] ?? null,
                                'location' => $targetUser['location'] ?? null,
                                'zipcode' => $targetUser['zipcode'] ?? null,
                                'work' => $targetUser['work'] ?? null,
                                'school' => $targetUser['school'] ?? null,
                                'hometown' => $targetUser['hometown'] ?? null,
                                'relationship_status' => $targetUser['relationship_status'] ?? null,
                                'avatar_url' => $targetUser['avatar_url'] ?? null,
                                'banner_url' => $targetUser['banner_url'] ?? null,
                                'oauth_provider' => $targetUser['oauth_provider'] ?? null,
                                'firebase_uid' => $targetUser['firebase_uid'] ?? null
                            ]);
                            
                            $stmt = $pdo->prepare("
                                INSERT INTO deleted_users (original_user_id, email, first_name, last_name, profile_data, deletion_reason, original_created_at) 
                                VALUES (?, ?, ?, ?, ?, 'admin_deleted', ?)
                                ON CONFLICT (email) DO UPDATE SET 
                                    original_user_id = EXCLUDED.original_user_id,
                                    first_name = EXCLUDED.first_name,
                                    last_name = EXCLUDED.last_name,
                                    profile_data = EXCLUDED.profile_data,
                                    deletion_reason = 'admin_deleted',
                                    deleted_at = NOW(),
                                    original_created_at = EXCLUDED.original_created_at
                            ");
                            $stmt->execute([
                                $targetUser['id'],
                                $targetUser['email'],
                                $targetUser['first_name'],
                                $targetUser['last_name'],
                                $profileData,
                                $targetUser['created_at']
                            ]);
                        } catch (Exception $e) {
                            error_log('Archive insert skipped: ' . $e->getMessage());
                        }
                        
                        // Add to former_users table
                        try {
                            $stmt = $pdo->prepare("INSERT INTO former_users (email, reason) VALUES (?, 'admin_deleted') ON CONFLICT (email) DO NOTHING");
                            $stmt->execute([$targetUser['email']]);
                        } catch (Exception $e) {
                            error_log('Former users insert skipped: ' . $e->getMessage());
                        }
                        
                        // Delete posts and their images
                        $stmt = $pdo->prepare("SELECT image_url FROM posts WHERE user_id = ?");
                        $stmt->execute([$userId]);
                        $posts = $stmt->fetchAll();
                        foreach ($posts as $post) {
                            if (!empty($post['image_url']) && file_exists($post['image_url'])) {
                                @unlink($post['image_url']);
                            }
                        }
                        $stmt = $pdo->prepare("DELETE FROM posts WHERE user_id = ?");
                        $stmt->execute([$userId]);
                        
                        // Delete stories and their media
                        $stmt = $pdo->prepare("SELECT media_url FROM stories WHERE user_id = ?");
                        $stmt->execute([$userId]);
                        $stories = $stmt->fetchAll();
                        foreach ($stories as $story) {
                            if (!empty($story['media_url']) && file_exists($story['media_url'])) {
                                @unlink($story['media_url']);
                            }
                        }
                        $stmt = $pdo->prepare("DELETE FROM stories WHERE user_id = ?");
                        $stmt->execute([$userId]);
                        
                        // Delete avatar and banner files
                        if (!empty($targetUser['avatar_url']) && file_exists($targetUser['avatar_url'])) {
                            @unlink($targetUser['avatar_url']);
                        }
                        if (!empty($targetUser['banner_url']) && file_exists($targetUser['banner_url'])) {
                            @unlink($targetUser['banner_url']);
                        }
                        
                        // Clean up related data
                        $tablesToClean = [
                            ['DELETE FROM reactions WHERE user_id = ?', [$userId]],
                            ['DELETE FROM live_room_participants WHERE user_id = ?', [$userId]],
                            ['DELETE FROM live_room_messages WHERE user_id = ?', [$userId]],
                            ['DELETE FROM notifications WHERE user_id = ? OR actor_id = ?', [$userId, $userId]],
                            ['DELETE FROM comments WHERE user_id = ?', [$userId]],
                            ['DELETE FROM friendships WHERE user_id = ? OR friend_id = ?', [$userId, $userId]],
                            ['DELETE FROM friend_requests WHERE sender_id = ? OR receiver_id = ?', [$userId, $userId]],
                            ['DELETE FROM pokes WHERE poker_id = ? OR poked_id = ?', [$userId, $userId]],
                            ['DELETE FROM rate_limits WHERE user_id = ?', [$userId]],
                        ];
                        
                        foreach ($tablesToClean as $query) {
                            try {
                                $stmt = $pdo->prepare($query[0]);
                                $stmt->execute($query[1]);
                            } catch (Exception $e) {
                                error_log('Cleanup skipped: ' . $e->getMessage());
                            }
                        }
                        
                        // Delete the user
                        $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
                        $stmt->execute([$userId]);
                        
                        header('Location: admin.php?tab=users&user_deleted=1');
                        exit;
                    }
                }
                header('Location: admin.php?tab=users&delete_error=1');
                exit;
                
            case 'update_rate_limits':
                $friendLimit = intval($_POST['friend_request_limit'] ?? 25);
                $friendWindow = intval($_POST['friend_request_window'] ?? 24);
                $postLimit = intval($_POST['post_limit'] ?? 100);
                $postWindow = intval($_POST['post_window'] ?? 24);
                
                // Ensure site_settings table exists
                $pdo->exec("CREATE TABLE IF NOT EXISTS site_settings (
                    id SERIAL PRIMARY KEY,
                    setting_key VARCHAR(100) UNIQUE NOT NULL,
                    setting_value TEXT,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                )");
                
                // Update each setting
                $settings = [
                    'rate_limit_friend_request_limit' => $friendLimit,
                    'rate_limit_friend_request_window' => $friendWindow,
                    'rate_limit_post_limit' => $postLimit,
                    'rate_limit_post_window' => $postWindow
                ];
                
                foreach ($settings as $key => $value) {
                    $stmt = $pdo->prepare("
                        INSERT INTO site_settings (setting_key, setting_value, updated_at)
                        VALUES (?, ?, NOW())
                        ON CONFLICT (setting_key) DO UPDATE SET setting_value = ?, updated_at = NOW()
                    ");
                    $stmt->execute([$key, $value, $value]);
                }
                
                header('Location: admin.php?tab=users&rate_limits_updated=1');
                exit;
                
            case 'verify_band':
                $bandId = intval($_POST['band_id'] ?? 0);
                if ($bandId) {
                    $stmt = $pdo->prepare("UPDATE bands SET is_verified = true, verification_status = 'verified', verified_at = NOW(), verified_by = ? WHERE id = ?");
                    $stmt->execute([$user['id'], $bandId]);
                    header('Location: admin.php?tab=bands&band_verified=1');
                    exit;
                }
                break;
                
            case 'reject_band':
                $bandId = intval($_POST['band_id'] ?? 0);
                if ($bandId) {
                    $stmt = $pdo->prepare("UPDATE bands SET is_verified = false, verification_status = 'rejected', verified_at = NOW(), verified_by = ? WHERE id = ?");
                    $stmt->execute([$user['id'], $bandId]);
                    header('Location: admin.php?tab=bands&band_rejected=1');
                    exit;
                }
                break;
                
            case 'delete_band':
                $bandId = intval($_POST['band_id'] ?? 0);
                if ($bandId) {
                    $stmt = $pdo->prepare("DELETE FROM bands WHERE id = ?");
                    $stmt->execute([$bandId]);
                    header('Location: admin.php?tab=bands&band_deleted=1');
                    exit;
                }
                break;
                
            case 'add_genre':
                $name = trim($_POST['genre_name'] ?? '');
                $displayOrder = intval($_POST['display_order'] ?? 0);
                if (!empty($name)) {
                    $slug = strtolower(preg_replace('/[^a-zA-Z0-9]+/', '-', $name));
                    $slug = trim($slug, '-');
                    try {
                        $stmt = $pdo->prepare("INSERT INTO band_genres (name, slug, display_order, is_active) VALUES (?, ?, ?, true)");
                        $stmt->execute([$name, $slug, $displayOrder]);
                        header('Location: admin.php?tab=genres&genre_added=1');
                    } catch (Exception $e) {
                        header('Location: admin.php?tab=genres&genre_error=duplicate');
                    }
                    exit;
                }
                header('Location: admin.php?tab=genres&genre_error=empty');
                exit;
                
            case 'update_genre':
                $genreId = intval($_POST['genre_id'] ?? 0);
                $name = trim($_POST['genre_name'] ?? '');
                $displayOrder = intval($_POST['display_order'] ?? 0);
                $isActive = isset($_POST['is_active']) ? true : false;
                if ($genreId && !empty($name)) {
                    $slug = strtolower(preg_replace('/[^a-zA-Z0-9]+/', '-', $name));
                    $slug = trim($slug, '-');
                    try {
                        $stmt = $pdo->prepare("UPDATE band_genres SET name = ?, slug = ?, display_order = ?, is_active = ? WHERE id = ?");
                        $stmt->execute([$name, $slug, $displayOrder, $isActive, $genreId]);
                        header('Location: admin.php?tab=genres&genre_updated=1');
                    } catch (Exception $e) {
                        header('Location: admin.php?tab=genres&genre_error=duplicate');
                    }
                    exit;
                }
                header('Location: admin.php?tab=genres');
                exit;
                
            case 'delete_genre':
                $genreId = intval($_POST['genre_id'] ?? 0);
                if ($genreId) {
                    $stmt = $pdo->prepare("DELETE FROM band_genres WHERE id = ?");
                    $stmt->execute([$genreId]);
                    header('Location: admin.php?tab=genres&genre_deleted=1');
                    exit;
                }
                break;
                
            case 'toggle_test_mode':
                $enabled = isset($_POST['test_mode_enabled']) ? 'true' : 'false';
                $stmt = $pdo->prepare("
                    INSERT INTO site_settings (setting_key, setting_value, updated_at)
                    VALUES ('checkout_test_mode', ?, NOW())
                    ON CONFLICT (setting_key) DO UPDATE SET setting_value = ?, updated_at = NOW()
                ");
                $stmt->execute([$enabled, $enabled]);
                header('Location: admin.php?tab=orders&test_mode_updated=1');
                exit;
                
            case 'add_contest':
                $title = trim($_POST['title'] ?? '');
                $content = $_POST['content'] ?? '';
                $displayLocation = $_POST['display_location'] ?? 'none';
                $headerTitle = trim($_POST['header_title'] ?? '');
                $headerTitleColor = $_POST['header_title_color'] ?? '#00ffff';
                $headerTitleSize = $_POST['header_title_size'] ?? '12px';
                $imageUrl = null;
                $iconUrl = null;
                
                if (empty($title)) {
                    header('Location: admin.php?tab=contests&error=title_required');
                    exit;
                }
                
                // Handle image upload (for feed)
                if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
                    $file = $_FILES['image'];
                    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
                    $finfo = finfo_open(FILEINFO_MIME_TYPE);
                    $mimeType = finfo_file($finfo, $file['tmp_name']);
                    finfo_close($finfo);
                    
                    if (in_array($mimeType, $allowedTypes)) {
                        $imageUrl = uploadFileToObjectStorage($file['tmp_name'], $mimeType, 'contests');
                    }
                }
                
                // Handle icon upload (for header)
                if (isset($_FILES['icon']) && $_FILES['icon']['error'] === UPLOAD_ERR_OK) {
                    $file = $_FILES['icon'];
                    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
                    $finfo = finfo_open(FILEINFO_MIME_TYPE);
                    $mimeType = finfo_file($finfo, $file['tmp_name']);
                    finfo_close($finfo);
                    
                    if (in_array($mimeType, $allowedTypes)) {
                        $iconUrl = uploadFileToObjectStorage($file['tmp_name'], $mimeType, 'contest-icons');
                    }
                }
                
                $showInFeed = in_array($displayLocation, ['feed', 'both']) ? true : false;
                $expiresAt = !empty($_POST['expires_at']) ? $_POST['expires_at'] : null;
                
                $stmt = $pdo->prepare("INSERT INTO contests (title, content, image_url, display_location, icon_url, header_title, header_title_color, header_title_size, show_in_feed, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?::boolean, ?)");
                $stmt->execute([$title, $content, $imageUrl, $displayLocation, $iconUrl, $headerTitle, $headerTitleColor, $headerTitleSize, $showInFeed ? 't' : 'f', $expiresAt]);
                header('Location: admin.php?tab=contests&contest_added=1');
                exit;
                
            case 'update_contest':
                $contestId = intval($_POST['contest_id'] ?? 0);
                $title = trim($_POST['title'] ?? '');
                $content = $_POST['content'] ?? '';
                $isActive = isset($_POST['is_active']) ? true : false;
                $displayLocation = $_POST['display_location'] ?? 'none';
                $headerTitle = trim($_POST['header_title'] ?? '');
                $headerTitleColor = $_POST['header_title_color'] ?? '#00ffff';
                $headerTitleSize = $_POST['header_title_size'] ?? '12px';
                
                if (!$contestId || empty($title)) {
                    header('Location: admin.php?tab=contests&error=invalid');
                    exit;
                }
                
                // Handle image upload if new image provided
                $imageUrl = null;
                if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
                    $file = $_FILES['image'];
                    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
                    $finfo = finfo_open(FILEINFO_MIME_TYPE);
                    $mimeType = finfo_file($finfo, $file['tmp_name']);
                    finfo_close($finfo);
                    
                    if (in_array($mimeType, $allowedTypes)) {
                        $imageUrl = uploadFileToObjectStorage($file['tmp_name'], $mimeType, 'contests');
                    }
                }
                
                // Handle icon upload if new icon provided
                $iconUrl = null;
                if (isset($_FILES['icon']) && $_FILES['icon']['error'] === UPLOAD_ERR_OK) {
                    $file = $_FILES['icon'];
                    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
                    $finfo = finfo_open(FILEINFO_MIME_TYPE);
                    $mimeType = finfo_file($finfo, $file['tmp_name']);
                    finfo_close($finfo);
                    
                    if (in_array($mimeType, $allowedTypes)) {
                        $iconUrl = uploadFileToObjectStorage($file['tmp_name'], $mimeType, 'contest-icons');
                    }
                }
                
                $showInFeed = in_array($displayLocation, ['feed', 'both']) ? true : false;
                $expiresAt = !empty($_POST['expires_at']) ? $_POST['expires_at'] : null;
                
                // Build update query dynamically based on what's being updated
                $updateFields = ['title = ?', 'content = ?', 'is_active = ?', 'display_location = ?', 'header_title = ?', 'header_title_color = ?', 'header_title_size = ?', 'show_in_feed = ?::boolean', 'expires_at = ?', 'updated_at = NOW()'];
                $params = [$title, $content, $isActive, $displayLocation, $headerTitle, $headerTitleColor, $headerTitleSize, $showInFeed ? 't' : 'f', $expiresAt];
                
                if ($imageUrl) {
                    $updateFields[] = 'image_url = ?';
                    $params[] = $imageUrl;
                }
                if ($iconUrl) {
                    $updateFields[] = 'icon_url = ?';
                    $params[] = $iconUrl;
                }
                
                $params[] = $contestId;
                $sql = "UPDATE contests SET " . implode(', ', $updateFields) . " WHERE id = ?";
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);
                
                header('Location: admin.php?tab=contests&contest_updated=1');
                exit;
                
            case 'delete_contest':
                $contestId = intval($_POST['contest_id'] ?? 0);
                if ($contestId) {
                    $stmt = $pdo->prepare("DELETE FROM contests WHERE id = ?");
                    $stmt->execute([$contestId]);
                    header('Location: admin.php?tab=contests&contest_deleted=1');
                    exit;
                }
                break;
        }
    }
}

$activeTab = $_GET['tab'] ?? 'reviews';
$bannedWords = $moderator->getBannedWords();
$pendingReviews = $moderator->getPendingReviews();

// Get all users for user management with rate limit info
$usersStmt = $pdo->query("
    SELECT u.id, u.email, u.first_name, u.last_name, u.is_admin, u.is_founder, u.is_active, u.email_verified, u.created_at, u.last_login,
           rl_fr.action_count as friend_request_count,
           rl_fr.window_start as friend_request_window,
           rl_post.action_count as post_count,
           rl_post.window_start as post_window
    FROM users u
    LEFT JOIN rate_limits rl_fr ON u.id = rl_fr.user_id AND rl_fr.action_type = 'friend_request'
    LEFT JOIN rate_limits rl_post ON u.id = rl_post.user_id AND rl_post.action_type = 'post'
    ORDER BY u.created_at DESC
");

// Get rate limit settings (use consistent short keys)
$rateLimitSettings = [
    'friend_request_limit' => 25,
    'friend_request_window' => 24,
    'post_limit' => 100,
    'post_window' => 24
];
try {
    $settingsStmt = $pdo->query("SELECT setting_key, setting_value FROM site_settings WHERE setting_key LIKE 'rate_limit_%'");
    while ($setting = $settingsStmt->fetch()) {
        // Strip 'rate_limit_' prefix for consistent short keys
        $shortKey = str_replace('rate_limit_', '', $setting['setting_key']);
        $rateLimitSettings[$shortKey] = intval($setting['setting_value']);
    }
} catch (Exception $e) {
    // Table may not exist yet
}
$allUsers = $usersStmt->fetchAll();

$pageTitle = 'Admin Panel - ' . SITE_NAME;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo h(SITE_TITLE); ?></title>
    <link rel="stylesheet" href="css/style.css">
    <link href="https://cdn.quilljs.com/1.3.7/quill.snow.css" rel="stylesheet">
    <script src="https://cdn.quilljs.com/1.3.7/quill.min.js"></script>
    <style>
        .admin-container {
            max-width: 1200px;
            margin: 20px auto;
            padding: 0 20px;
        }
        .admin-header {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .admin-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        .admin-tab {
            padding: 10px 20px;
            background: #e4e6e9;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            text-decoration: none;
            color: #050505;
        }
        .admin-tab.active {
            background: #1877f2;
            color: white;
        }
        .admin-content {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .word-list {
            list-style: none;
            padding: 0;
        }
        .word-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            border-bottom: 1px solid #e4e6e9;
        }
        .word-item:last-child {
            border-bottom: none;
        }
        .severity-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        .severity-high { background: #ffe5e5; color: #e41e3f; }
        .severity-medium { background: #fff4e5; color: #f59e0b; }
        .severity-low { background: #e5f3ff; color: #1877f2; }
        
        .sortable:hover { background: #e4e6e9; }
        .sortable .sort-arrow { margin-left: 4px; font-size: 10px; }
        .sortable.asc .sort-arrow::after { content: '▲'; }
        .sortable.desc .sort-arrow::after { content: '▼'; }
        .review-card {
            border: 1px solid #e4e6e9;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
        }
        .review-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            padding-bottom: 10px;
            border-bottom: 1px solid #e4e6e9;
        }
        .form-group {
            margin-bottom: 15px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
        }
        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
        }
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
        }
        .btn-primary {
            background: #1877f2;
            color: white;
        }
        .btn-success {
            background: #48bb78;
            color: white;
        }
        .btn-danger {
            background: #e41e3f;
            color: white;
        }
        .btn-secondary {
            background: #e4e6e9;
            color: #050505;
        }
        .alert {
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 15px;
        }
        .alert-success {
            background: #d4edda;
            color: #155724;
        }
    </style>
</head>
<body>
    <div class="admin-container">
        <div class="admin-header">
            <h1>Admin Panel</h1>
            <p>Welcome, <?php echo h($user['first_name'] . ' ' . $user['last_name']); ?> | <a href="home.php">Back to Home</a></p>
        </div>

        <div class="admin-tabs">
            <a href="?tab=users" class="admin-tab <?php echo $activeTab === 'users' ? 'active' : ''; ?>">
                Users (<?php echo count($allUsers); ?>)
            </a>
            <a href="?tab=reviews" class="admin-tab <?php echo $activeTab === 'reviews' ? 'active' : ''; ?>">
                Content Reviews (<?php echo count($pendingReviews); ?>)
            </a>
            <a href="?tab=words" class="admin-tab <?php echo $activeTab === 'words' ? 'active' : ''; ?>">
                Banned Words (<?php echo count($bannedWords); ?>)
            </a>
            <a href="?tab=products" class="admin-tab <?php echo $activeTab === 'products' ? 'active' : ''; ?>">
                POD Products
            </a>
            <?php
            $pendingOrdersCount = 0;
            try {
                $stmt = $pdo->query("SELECT COUNT(*) FROM custom_orders WHERE printify_order_id IS NOT NULL AND printify_status NOT IN ('fulfilled', 'canceled')");
                $pendingOrdersCount = $stmt->fetchColumn();
            } catch (Exception $e) {}
            ?>
            <a href="?tab=orders" class="admin-tab <?php echo $activeTab === 'orders' ? 'active' : ''; ?>">
                POD Orders<?php echo $pendingOrdersCount > 0 ? " ({$pendingOrdersCount})" : ''; ?>
            </a>
            <a href="?tab=catalog" class="admin-tab <?php echo $activeTab === 'catalog' ? 'active' : ''; ?>">
                Printify Catalog
            </a>
            <a href="?tab=digital" class="admin-tab <?php echo $activeTab === 'digital' ? 'active' : ''; ?>">
                Digital Products
            </a>
            <a href="?tab=news" class="admin-tab <?php echo $activeTab === 'news' ? 'active' : ''; ?>">
                News Articles
            </a>
            <a href="?tab=backgrounds" class="admin-tab <?php echo $activeTab === 'backgrounds' ? 'active' : ''; ?>">
                Backgrounds
            </a>
            <a href="?tab=interactions" class="admin-tab <?php echo $activeTab === 'interactions' ? 'active' : ''; ?>">
                Interactions
            </a>
            <a href="?tab=carousels" class="admin-tab <?php echo $activeTab === 'carousels' ? 'active' : ''; ?>">
                Feed Carousels
            </a>
            <a href="?tab=shorts" class="admin-tab <?php echo $activeTab === 'shorts' ? 'active' : ''; ?>">
                Shorts Scraper
            </a>
            <a href="?tab=contests" class="admin-tab <?php echo $activeTab === 'contests' ? 'active' : ''; ?>">
                Contests
            </a>
            <a href="?tab=polls" class="admin-tab <?php echo $activeTab === 'polls' ? 'active' : ''; ?>">
                Polls
            </a>
            <?php
            $pendingBandsCount = 0;
            $allBandsCount = 0;
            try {
                $stmt = $pdo->query("SELECT COUNT(*) FROM bands WHERE verification_status = 'pending'");
                $pendingBandsCount = $stmt->fetchColumn();
                $stmt = $pdo->query("SELECT COUNT(*) FROM bands");
                $allBandsCount = $stmt->fetchColumn();
            } catch (Exception $e) {}
            ?>
            <a href="?tab=bands" class="admin-tab <?php echo $activeTab === 'bands' ? 'active' : ''; ?>">
                Bands (<?php echo $pendingBandsCount; ?> pending)
            </a>
            <?php
            $genresCount = 0;
            try {
                $stmt = $pdo->query("SELECT COUNT(*) FROM band_genres");
                $genresCount = $stmt->fetchColumn();
            } catch (Exception $e) {}
            ?>
            <a href="?tab=genres" class="admin-tab <?php echo $activeTab === 'genres' ? 'active' : ''; ?>">
                Genres (<?php echo $genresCount; ?>)
            </a>
        </div>

        <div class="admin-content">
            <?php if (isset($_GET['error']) && $_GET['error'] === 'csrf'): ?>
                <div class="alert" style="background: #ffe5e5; color: #e41e3f;">Security validation failed. Please try again.</div>
            <?php endif; ?>

            <?php if (isset($_GET['success'])): ?>
                <div class="alert alert-success">Word added successfully!</div>
            <?php endif; ?>

            <?php if (isset($_GET['deleted'])): ?>
                <div class="alert alert-success">Word removed successfully!</div>
            <?php endif; ?>

            <?php if (isset($_GET['reviewed'])): ?>
                <div class="alert alert-success">Content reviewed successfully!</div>
            <?php endif; ?>

            <?php if (isset($_GET['updated'])): ?>
                <div class="alert alert-success">User updated successfully!</div>
            <?php endif; ?>

            <?php if (isset($_GET['password_reset'])): ?>
                <div class="alert alert-success">Password reset successfully!</div>
            <?php endif; ?>

            <?php if (isset($_GET['password_error'])): ?>
                <div class="alert" style="background: #ffe5e5; color: #e41e3f;">Password must be at least 8 characters.</div>
            <?php endif; ?>

            <?php if (isset($_GET['user_deleted'])): ?>
                <div class="alert alert-success">User deleted successfully!</div>
            <?php endif; ?>

            <?php if (isset($_GET['delete_error'])): ?>
                <div class="alert" style="background: #ffe5e5; color: #e41e3f;">Could not delete user. You cannot delete your own account.</div>
            <?php endif; ?>

            <?php if (isset($_GET['unlocked'])): ?>
                <div class="alert alert-success">User rate limits have been reset!</div>
            <?php endif; ?>

            <?php if (isset($_GET['rate_limits_updated'])): ?>
                <div class="alert alert-success">Rate limit settings updated successfully!</div>
            <?php endif; ?>

            <?php if (isset($_GET['synced'])): ?>
                <div class="alert alert-success">Printify sync completed! <?php echo intval($_GET['synced']); ?> products synced.</div>
            <?php endif; ?>

            <?php if (isset($_GET['sync_error'])): ?>
                <div class="alert" style="background: #ffe5e5; color: #e41e3f;">Sync failed. Please check your Printify API key.</div>
            <?php endif; ?>

            <?php if ($activeTab === 'users'): ?>
                <h2>User Management</h2>
                <p style="color: #65676b; margin-bottom: 20px;">Manage user roles and permissions. Founders have special privileges on the platform. Click column headers to sort.</p>
                
                <!-- Rate Limit Settings -->
                <div style="background: #f8f9fa; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
                    <h3 style="margin: 0 0 15px 0; font-size: 16px; color: #333;">Rate Limit Settings</h3>
                    <form method="POST" style="display: flex; flex-wrap: wrap; gap: 20px; align-items: flex-end;">
                        <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                        <input type="hidden" name="action" value="update_rate_limits">
                        <div>
                            <label style="display: block; font-size: 13px; color: #666; margin-bottom: 5px;">Friend Requests (per window)</label>
                            <input type="number" name="friend_request_limit" value="<?php echo $rateLimitSettings['friend_request_limit']; ?>" min="1" max="1000" style="width: 80px; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        </div>
                        <div>
                            <label style="display: block; font-size: 13px; color: #666; margin-bottom: 5px;">Window (hours)</label>
                            <input type="number" name="friend_request_window" value="<?php echo $rateLimitSettings['friend_request_window']; ?>" min="1" max="168" style="width: 80px; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        </div>
                        <div style="border-left: 1px solid #ddd; padding-left: 20px;">
                            <label style="display: block; font-size: 13px; color: #666; margin-bottom: 5px;">Posts (per window)</label>
                            <input type="number" name="post_limit" value="<?php echo $rateLimitSettings['post_limit']; ?>" min="1" max="1000" style="width: 80px; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        </div>
                        <div>
                            <label style="display: block; font-size: 13px; color: #666; margin-bottom: 5px;">Window (hours)</label>
                            <input type="number" name="post_window" value="<?php echo $rateLimitSettings['post_window']; ?>" min="1" max="168" style="width: 80px; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        </div>
                        <button type="submit" class="btn btn-primary" style="padding: 8px 16px;">Save Settings</button>
                    </form>
                </div>
                
                <!-- Printify Webhook Settings -->
                <div style="background: #f8f9fa; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
                    <h3 style="margin: 0 0 15px 0; font-size: 16px; color: #333;">Printify Shipping Notifications</h3>
                    <p style="color: #666; font-size: 13px; margin-bottom: 15px;">Set up webhooks so customers get automatic email notifications when their orders ship.</p>
                    
                    <?php
                    // Handle webhook registration
                    if (isset($_POST['action']) && $_POST['action'] === 'register_printify_webhooks') {
                        $apiToken = getenv('PRINTIFY_API_KEY') ?: getenv('PRINTIFY_API_TOKEN');
                        $shopId = getenv('PRINTIFY_SHOP_ID');
                        
                        if ($apiToken && !$shopId) {
                            $ch = curl_init('https://api.printify.com/v1/shops.json');
                            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => ["Authorization: Bearer {$apiToken}"]]);
                            $shopsResponse = curl_exec($ch);
                            curl_close($ch);
                            $shops = json_decode($shopsResponse, true);
                            if (!empty($shops) && isset($shops[0]['id'])) $shopId = $shops[0]['id'];
                        }
                        
                        if ($apiToken && $shopId) {
                            $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
                            $webhookUrl = "{$protocol}://{$_SERVER['HTTP_HOST']}/api/printify-webhook.php";
                            $topics = ['order:created', 'order:updated', 'order:sent-to-production', 'order:shipment:created', 'order:shipment:delivered'];
                            $registered = 0;
                            
                            foreach ($topics as $topic) {
                                $ch = curl_init("https://api.printify.com/v1/shops/{$shopId}/webhooks.json");
                                curl_setopt_array($ch, [
                                    CURLOPT_RETURNTRANSFER => true,
                                    CURLOPT_POST => true,
                                    CURLOPT_POSTFIELDS => json_encode(['topic' => $topic, 'url' => $webhookUrl]),
                                    CURLOPT_HTTPHEADER => ["Authorization: Bearer {$apiToken}", "Content-Type: application/json"]
                                ]);
                                $response = curl_exec($ch);
                                $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                                curl_close($ch);
                                if ($httpCode >= 200 && $httpCode < 300) $registered++;
                            }
                            echo '<div style="margin-bottom: 15px; padding: 10px; background: #d4edda; border: 1px solid #c3e6cb; border-radius: 4px; color: #155724;">Registered ' . $registered . ' of ' . count($topics) . ' webhooks successfully!</div>';
                        } else {
                            echo '<div style="margin-bottom: 15px; padding: 10px; background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 4px; color: #721c24;">Missing Printify API key or shop ID.</div>';
                        }
                    }
                    
                    // Check current webhooks
                    $webhookStatus = '';
                    $apiToken = getenv('PRINTIFY_API_KEY') ?: getenv('PRINTIFY_API_TOKEN');
                    $shopId = getenv('PRINTIFY_SHOP_ID');
                    
                    if ($apiToken) {
                        if (!$shopId) {
                            $ch = curl_init('https://api.printify.com/v1/shops.json');
                            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => ["Authorization: Bearer {$apiToken}"]]);
                            $shopsResponse = curl_exec($ch);
                            curl_close($ch);
                            $shops = json_decode($shopsResponse, true);
                            if (!empty($shops) && isset($shops[0]['id'])) $shopId = $shops[0]['id'];
                        }
                        
                        if ($shopId) {
                            $ch = curl_init("https://api.printify.com/v1/shops/{$shopId}/webhooks.json");
                            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => ["Authorization: Bearer {$apiToken}"]]);
                            $response = curl_exec($ch);
                            curl_close($ch);
                            $webhooks = json_decode($response, true);
                            
                            if (is_array($webhooks) && count($webhooks) > 0) {
                                $webhookStatus = '<span style="color: #28a745;">Active webhooks (' . count($webhooks) . '):</span><ul style="margin: 5px 0 0 20px;">';
                                foreach ($webhooks as $wh) {
                                    $webhookStatus .= '<li>' . h($wh['topic'] ?? 'unknown') . '</li>';
                                }
                                $webhookStatus .= '</ul>';
                            } else {
                                $webhookStatus = '<span style="color: #ffc107;">No webhooks configured yet. Click the button below to enable.</span>';
                            }
                        } else {
                            $webhookStatus = '<span style="color: #dc3545;">Could not find Printify shop. Check your API key.</span>';
                        }
                    } else {
                        $webhookStatus = '<span style="color: #dc3545;">PRINTIFY_API_KEY not configured in secrets.</span>';
                    }
                    ?>
                    
                    <div style="margin-bottom: 15px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px; font-size: 13px;">
                        <?php echo $webhookStatus; ?>
                    </div>
                    
                    <form method="POST" style="display: inline;">
                        <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                        <input type="hidden" name="action" value="register_printify_webhooks">
                        <button type="submit" class="btn btn-primary" style="padding: 8px 16px;">Enable Shipping Notifications</button>
                    </form>
                </div>
                
                <form id="resetPasswordForm" method="POST" style="display: none;">
                    <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                    <input type="hidden" name="action" value="reset_password">
                    <input type="hidden" name="user_id" id="resetUserId">
                    <input type="hidden" name="new_password" id="resetNewPassword">
                </form>
                
                <form id="deleteUserForm" method="POST" style="display: none;">
                    <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                    <input type="hidden" name="action" value="delete_user">
                    <input type="hidden" name="user_id" id="deleteUserId">
                </form>
                
                <script>
                function resetPassword(userId, userName) {
                    const newPassword = prompt('Enter new password for ' + userName + ' (minimum 8 characters):');
                    if (newPassword === null) return;
                    if (newPassword.length < 8) {
                        alert('Password must be at least 8 characters.');
                        return;
                    }
                    if (!confirm('Are you sure you want to reset the password for ' + userName + '?')) return;
                    
                    document.getElementById('resetUserId').value = userId;
                    document.getElementById('resetNewPassword').value = newPassword;
                    document.getElementById('resetPasswordForm').submit();
                }
                
                function deleteUser(userId, userName) {
                    if (!confirm('Are you sure you want to delete the account for ' + userName + '? This will permanently remove all their posts, stories, comments, and other data. This action cannot be undone.')) return;
                    if (!confirm('This is your final warning. Delete ' + userName + '\'s account permanently?')) return;
                    
                    document.getElementById('deleteUserId').value = userId;
                    document.getElementById('deleteUserForm').submit();
                }
                </script>
                
                <table id="usersTable" style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background: #f0f2f5; text-align: left;">
                            <th class="sortable" data-column="name" style="padding: 12px; border-bottom: 2px solid #ddd; cursor: pointer;">User <span class="sort-arrow"></span></th>
                            <th class="sortable" data-column="email" style="padding: 12px; border-bottom: 2px solid #ddd; cursor: pointer;">Email <span class="sort-arrow"></span></th>
                            <th class="sortable" data-column="joined" style="padding: 12px; border-bottom: 2px solid #ddd; cursor: pointer;">Joined <span class="sort-arrow"></span></th>
                            <th style="padding: 12px; border-bottom: 2px solid #ddd; text-align: center;">Rate Limits</th>
                            <th class="sortable" data-column="active" style="padding: 12px; border-bottom: 2px solid #ddd; text-align: center; cursor: pointer;">Active <span class="sort-arrow"></span></th>
                            <th class="sortable" data-column="admin" style="padding: 12px; border-bottom: 2px solid #ddd; text-align: center; cursor: pointer;">Admin <span class="sort-arrow"></span></th>
                            <th class="sortable" data-column="founder" style="padding: 12px; border-bottom: 2px solid #ddd; text-align: center; cursor: pointer;">Founder <span class="sort-arrow"></span></th>
                            <th class="sortable" data-column="verified" style="padding: 12px; border-bottom: 2px solid #ddd; text-align: center; cursor: pointer;">Verified <span class="sort-arrow"></span></th>
                            <th style="padding: 12px; border-bottom: 2px solid #ddd; text-align: center;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($allUsers as $u): ?>
                        <tr style="border-bottom: 1px solid #e4e6e9;" 
                            data-name="<?php echo h(strtolower($u['first_name'] . ' ' . $u['last_name'])); ?>"
                            data-email="<?php echo h(strtolower($u['email'])); ?>"
                            data-joined="<?php echo $u['created_at']; ?>"
                            data-active="<?php echo $u['is_active'] ? '1' : '0'; ?>"
                            data-admin="<?php echo $u['is_admin'] ? '1' : '0'; ?>"
                            data-founder="<?php echo $u['is_founder'] ? '1' : '0'; ?>"
                            data-verified="<?php echo $u['email_verified'] ? '1' : '0'; ?>">
                            <td style="padding: 12px;">
                                <strong><?php echo h($u['first_name'] . ' ' . $u['last_name']); ?></strong>
                            </td>
                            <td style="padding: 12px; color: #65676b;"><?php echo h($u['email']); ?></td>
                            <td style="padding: 12px; color: #65676b; font-size: 13px;">
                                <?php echo date('M j, Y', strtotime($u['created_at'])); ?>
                            </td>
                            <td style="padding: 12px; text-align: center;">
                                <?php
                                $frLimit = $rateLimitSettings['friend_request_limit'];
                                $postLimit = $rateLimitSettings['post_limit'];
                                $frWindowHours = $rateLimitSettings['friend_request_window'];
                                $postWindowHours = $rateLimitSettings['post_window'];
                                
                                $frCount = intval($u['friend_request_count'] ?? 0);
                                $postCount = intval($u['post_count'] ?? 0);
                                
                                // Check if within active window
                                $now = time();
                                $frWindowActive = !empty($u['friend_request_window']) && 
                                    (strtotime($u['friend_request_window']) + ($frWindowHours * 3600)) > $now;
                                $postWindowActive = !empty($u['post_window']) && 
                                    (strtotime($u['post_window']) + ($postWindowHours * 3600)) > $now;
                                
                                $frAtLimit = $frWindowActive && $frCount >= $frLimit;
                                $postAtLimit = $postWindowActive && $postCount >= $postLimit;
                                ?>
                                <div style="font-size: 11px; line-height: 1.4;">
                                    <?php if ($frWindowActive && $frCount > 0): ?>
                                        <div style="display: flex; align-items: center; justify-content: center; gap: 4px; color: <?php echo $frAtLimit ? '#e41e3f' : '#666'; ?>;">
                                            <span>FR: <?php echo $frCount; ?>/<?php echo $frLimit; ?></span>
                                            <?php if ($frAtLimit): ?>
                                                <form method="POST" style="margin: 0;">
                                                    <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                                                    <input type="hidden" name="action" value="unlock_rate_limit">
                                                    <input type="hidden" name="user_id" value="<?php echo $u['id']; ?>">
                                                    <input type="hidden" name="limit_type" value="friend_request">
                                                    <button type="submit" class="btn btn-danger" style="font-size: 9px; padding: 2px 5px;">Unlock</button>
                                                </form>
                                            <?php endif; ?>
                                        </div>
                                    <?php endif; ?>
                                    <?php if ($postWindowActive && $postCount > 0): ?>
                                        <div style="display: flex; align-items: center; justify-content: center; gap: 4px; color: <?php echo $postAtLimit ? '#e41e3f' : '#666'; ?>;">
                                            <span>Posts: <?php echo $postCount; ?>/<?php echo $postLimit; ?></span>
                                            <?php if ($postAtLimit): ?>
                                                <form method="POST" style="margin: 0;">
                                                    <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                                                    <input type="hidden" name="action" value="unlock_rate_limit">
                                                    <input type="hidden" name="user_id" value="<?php echo $u['id']; ?>">
                                                    <input type="hidden" name="limit_type" value="post">
                                                    <button type="submit" class="btn btn-danger" style="font-size: 9px; padding: 2px 5px;">Unlock</button>
                                                </form>
                                            <?php endif; ?>
                                        </div>
                                    <?php endif; ?>
                                    <?php if (!$frWindowActive && !$postWindowActive): ?>
                                        <span style="color: #999;">-</span>
                                    <?php endif; ?>
                                </div>
                            </td>
                            <td style="padding: 12px; text-align: center;">
                                <form method="POST" style="margin: 0;">
                                    <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                                    <input type="hidden" name="action" value="update_user_role">
                                    <input type="hidden" name="user_id" value="<?php echo $u['id']; ?>">
                                    <input type="hidden" name="role" value="is_active">
                                    <input type="hidden" name="value" value="<?php echo $u['is_active'] ? '0' : '1'; ?>">
                                    <button type="submit" class="btn <?php echo $u['is_active'] ? 'btn-success' : 'btn-secondary'; ?>" style="min-width: 60px;">
                                        <?php echo $u['is_active'] ? 'Yes' : 'No'; ?>
                                    </button>
                                </form>
                            </td>
                            <td style="padding: 12px; text-align: center;">
                                <form method="POST" style="margin: 0;">
                                    <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                                    <input type="hidden" name="action" value="update_user_role">
                                    <input type="hidden" name="user_id" value="<?php echo $u['id']; ?>">
                                    <input type="hidden" name="role" value="is_admin">
                                    <input type="hidden" name="value" value="<?php echo $u['is_admin'] ? '0' : '1'; ?>">
                                    <button type="submit" class="btn <?php echo $u['is_admin'] ? 'btn-primary' : 'btn-secondary'; ?>" style="min-width: 60px;">
                                        <?php echo $u['is_admin'] ? 'Yes' : 'No'; ?>
                                    </button>
                                </form>
                            </td>
                            <td style="padding: 12px; text-align: center;">
                                <form method="POST" style="margin: 0;">
                                    <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                                    <input type="hidden" name="action" value="update_user_role">
                                    <input type="hidden" name="user_id" value="<?php echo $u['id']; ?>">
                                    <input type="hidden" name="role" value="is_founder">
                                    <input type="hidden" name="value" value="<?php echo $u['is_founder'] ? '0' : '1'; ?>">
                                    <button type="submit" class="btn <?php echo $u['is_founder'] ? 'btn-danger' : 'btn-secondary'; ?>" style="min-width: 60px;">
                                        <?php echo $u['is_founder'] ? 'Yes' : 'No'; ?>
                                    </button>
                                </form>
                            </td>
                            <td style="padding: 12px; text-align: center;">
                                <form method="POST" style="margin: 0;">
                                    <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                                    <input type="hidden" name="action" value="update_user_role">
                                    <input type="hidden" name="user_id" value="<?php echo $u['id']; ?>">
                                    <input type="hidden" name="role" value="email_verified">
                                    <input type="hidden" name="value" value="<?php echo $u['email_verified'] ? '0' : '1'; ?>">
                                    <button type="submit" class="btn <?php echo $u['email_verified'] ? 'btn-success' : 'btn-secondary'; ?>" style="min-width: 60px;">
                                        <?php echo $u['email_verified'] ? 'Yes' : 'No'; ?>
                                    </button>
                                </form>
                            </td>
                            <td style="padding: 12px; text-align: center;">
                                <div style="display: flex; gap: 5px; justify-content: center; flex-wrap: wrap;">
                                    <button type="button" class="btn btn-secondary" style="font-size: 12px;" onclick="resetPassword(<?php echo $u['id']; ?>, '<?php echo h($u['first_name'] . ' ' . $u['last_name']); ?>')">
                                        Reset Password
                                    </button>
                                    <?php if ($u['id'] !== $user['id']): ?>
                                    <button type="button" class="btn btn-danger" style="font-size: 12px;" onclick="deleteUser(<?php echo $u['id']; ?>, '<?php echo h($u['first_name'] . ' ' . $u['last_name']); ?>')">
                                        Delete
                                    </button>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>

            <?php elseif ($activeTab === 'reviews'): ?>
                <h2>Pending Content Reviews</h2>
                <?php if (empty($pendingReviews)): ?>
                    <p style="text-align: center; padding: 40px; color: #65676b;">No pending reviews</p>
                <?php else: ?>
                    <?php foreach ($pendingReviews as $review): ?>
                        <div class="review-card">
                            <div class="review-header">
                                <div>
                                    <strong><?php echo h($review['first_name'] . ' ' . $review['last_name']); ?></strong>
                                    <span style="color: #65676b;"> (<?php echo h($review['email']); ?>)</span>
                                </div>
                                <span style="color: #65676b; font-size: 14px;">
                                    <?php echo date('M j, Y g:i A', strtotime($review['created_at'])); ?>
                                </span>
                            </div>

                            <div style="margin-bottom: 15px;">
                                <strong>Content:</strong>
                                <div style="background: #f0f2f5; padding: 10px; border-radius: 6px; margin-top: 5px;">
                                    <?php echo nl2br(h($review['content'])); ?>
                                </div>
                            </div>

                            <div style="margin-bottom: 15px;">
                                <strong>Matched Words:</strong>
                                <div style="margin-top: 5px;">
                                    <?php
                                    $matched = json_decode($review['matched_words'], true);
                                    foreach ($matched as $match) {
                                        echo '<span class="severity-badge severity-' . h($match['severity']) . '">' . h($match['word']) . '</span> ';
                                    }
                                    ?>
                                </div>
                            </div>

                            <?php if ($review['review_message']): ?>
                                <div style="margin-bottom: 15px;">
                                    <strong>User's Explanation:</strong>
                                    <div style="background: #e5f3ff; padding: 10px; border-radius: 6px; margin-top: 5px;">
                                        <?php echo nl2br(h($review['review_message'])); ?>
                                    </div>
                                </div>
                            <?php endif; ?>

                            <form method="POST" style="display: flex; gap: 10px; align-items: flex-end;">
                                <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                                <input type="hidden" name="action" value="review_content">
                                <input type="hidden" name="flagged_id" value="<?php echo $review['id']; ?>">
                                <div class="form-group" style="flex: 1; margin: 0;">
                                    <label>Admin Notes:</label>
                                    <textarea name="notes" rows="2" placeholder="Optional notes..."></textarea>
                                </div>
                                <button type="submit" name="status" value="approved" class="btn btn-success">Approve</button>
                                <button type="submit" name="status" value="rejected" class="btn btn-danger">Reject</button>
                            </form>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>

            <?php elseif ($activeTab === 'words'): ?>
                <h2>Banned Words Management</h2>

                <form method="POST" style="margin-bottom: 30px; background: #f0f2f5; padding: 20px; border-radius: 8px;">
                    <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                    <input type="hidden" name="action" value="add_word">
                    <h3 style="margin-top: 0;">Add New Banned Word</h3>
                    <div style="display: flex; gap: 10px;">
                        <div class="form-group" style="flex: 2; margin: 0;">
                            <label>Word or Phrase:</label>
                            <input type="text" name="word" required placeholder="Enter offensive word">
                        </div>
                        <div class="form-group" style="flex: 1; margin: 0;">
                            <label>Severity:</label>
                            <select name="severity">
                                <option value="low">Low</option>
                                <option value="medium" selected>Medium</option>
                                <option value="high">High</option>
                            </select>
                        </div>
                        <div style="align-self: flex-end;">
                            <button type="submit" class="btn btn-primary">Add Word</button>
                        </div>
                    </div>
                </form>

                <h3>Current Banned Words (<?php echo count($bannedWords); ?>)</h3>
                <?php if (empty($bannedWords)): ?>
                    <p style="text-align: center; padding: 40px; color: #65676b;">No banned words yet</p>
                <?php else: ?>
                    <ul class="word-list">
                        <?php foreach ($bannedWords as $word): ?>
                            <li class="word-item">
                                <div>
                                    <strong><?php echo h($word['word']); ?></strong>
                                    <span class="severity-badge severity-<?php echo h($word['severity']); ?>">
                                        <?php echo h($word['severity']); ?>
                                    </span>
                                    <?php if ($word['first_name']): ?>
                                        <span style="color: #65676b; font-size: 13px;">
                                            Added by <?php echo h($word['first_name'] . ' ' . $word['last_name']); ?>
                                        </span>
                                    <?php endif; ?>
                                </div>
                                <form method="POST" style="margin: 0;">
                                    <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                                    <input type="hidden" name="action" value="remove_word">
                                    <input type="hidden" name="word_id" value="<?php echo $word['id']; ?>">
                                    <button type="submit" class="btn btn-secondary" onclick="return confirm('Remove this word?')">Remove</button>
                                </form>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>

            <?php elseif ($activeTab === 'news'): ?>
                <h2>News Articles</h2>
                <p style="color: #65676b; margin-bottom: 20px;">
                    Manage news articles displayed on the left and right sidebars of the community page. Drag to reorder articles within each section.
                </p>

                <div style="background: #f0f2f5; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h3 style="margin-top: 0;">Add New Article</h3>
                    <div style="display: grid; gap: 15px;">
                        <div class="form-group" style="margin-bottom: 0;">
                            <label for="articleTitle">Title</label>
                            <input type="text" id="articleTitle" placeholder="Enter article title...">
                        </div>
                        <div class="form-group" style="margin-bottom: 0;">
                            <label>Content</label>
                            <div id="articleContentEditor" style="height: 150px; background: white;"></div>
                        </div>
                        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px;">
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="articleAuthor">Author/Writer</label>
                                <input type="text" id="articleAuthor" placeholder="Author name...">
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="articleDate">Published Date</label>
                                <input type="date" id="articleDate">
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="articlePosition">Position</label>
                                <select id="articlePosition">
                                    <option value="left">Left Sidebar</option>
                                    <option value="right">Right Sidebar</option>
                                </select>
                            </div>
                        </div>
                        <button type="button" class="btn btn-primary" onclick="addNewsArticle()">Add Article</button>
                    </div>
                </div>

                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                    <div>
                        <h3>Left Sidebar Articles</h3>
                        <div id="leftArticlesList" class="articles-list" style="min-height: 100px; background: #f9f9f9; border-radius: 8px; padding: 10px;">
                            <p style="text-align: center; color: #65676b; padding: 20px;">Loading...</p>
                        </div>
                    </div>
                    <div>
                        <h3>Right Sidebar Articles</h3>
                        <div id="rightArticlesList" class="articles-list" style="min-height: 100px; background: #f9f9f9; border-radius: 8px; padding: 10px;">
                            <p style="text-align: center; color: #65676b; padding: 20px;">Loading...</p>
                        </div>
                    </div>
                </div>

                <style>
                    .article-card {
                        background: white;
                        border: 1px solid #e4e6e9;
                        border-radius: 8px;
                        padding: 15px;
                        margin-bottom: 10px;
                        cursor: grab;
                        transition: box-shadow 0.2s;
                    }
                    .article-card:hover {
                        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    }
                    .article-card.dragging {
                        opacity: 0.5;
                        cursor: grabbing;
                    }
                    .article-card-title {
                        font-weight: 600;
                        margin-bottom: 8px;
                        color: #1c1e21;
                    }
                    .article-card-preview {
                        font-size: 13px;
                        color: #65676b;
                        margin-bottom: 10px;
                        display: -webkit-box;
                        -webkit-line-clamp: 2;
                        -webkit-box-orient: vertical;
                        overflow: hidden;
                    }
                    .article-card-actions {
                        display: flex;
                        gap: 8px;
                    }
                    .article-card-actions button {
                        padding: 6px 12px;
                        font-size: 12px;
                    }
                    .drag-handle {
                        cursor: grab;
                        padding: 4px;
                        color: #65676b;
                    }
                </style>

                <script>
                let allArticles = [];
                let quillAdd, quillEdit;
                
                // Initialize Quill for adding articles
                quillAdd = new Quill('#articleContentEditor', {
                    theme: 'snow',
                    placeholder: 'Enter article content...',
                    modules: {
                        toolbar: [
                            ['bold', 'italic', 'underline'],
                            [{ 'list': 'ordered'}, { 'list': 'bullet' }],
                            ['link'],
                            ['clean']
                        ]
                    }
                });

                async function loadNewsArticles() {
                    try {
                        const response = await fetch('api/news-articles.php');
                        const data = await response.json();
                        if (data.success) {
                            allArticles = data.articles;
                            renderArticles();
                        }
                    } catch (error) {
                        console.error('Failed to load articles:', error);
                    }
                }

                function renderArticles() {
                    const leftList = document.getElementById('leftArticlesList');
                    const rightList = document.getElementById('rightArticlesList');
                    
                    const leftArticles = allArticles.filter(a => a.position === 'left');
                    const rightArticles = allArticles.filter(a => a.position === 'right');
                    
                    leftList.innerHTML = leftArticles.length === 0 
                        ? '<p style="text-align: center; color: #65676b; padding: 20px;">No articles</p>'
                        : leftArticles.map(a => articleCardHTML(a)).join('');
                    
                    rightList.innerHTML = rightArticles.length === 0 
                        ? '<p style="text-align: center; color: #65676b; padding: 20px;">No articles</p>'
                        : rightArticles.map(a => articleCardHTML(a)).join('');
                    
                    initDragAndDrop();
                }

                function articleCardHTML(article) {
                    return `
                        <div class="article-card" draggable="true" data-id="${article.id}" data-position="${article.position}">
                            <div style="display: flex; align-items: start; gap: 10px;">
                                <div class="drag-handle">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                        <path stroke-linecap="round" stroke-linejoin="round" d="M4 8h16M4 16h16" />
                                    </svg>
                                </div>
                                <div style="flex: 1;">
                                    <div class="article-card-title"><span style="color: #1877f2; font-weight: 600;">#${article.id}</span> ${escapeHtml(article.title)}</div>
                                    <div class="article-card-preview">${escapeHtml(stripHtml(article.content).substring(0, 100))}</div>
                                    <div class="article-card-actions">
                                        <button class="btn btn-secondary" onclick="editArticle(${article.id})">Edit</button>
                                        <button class="btn btn-danger" onclick="deleteArticle(${article.id})">Delete</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                }

                function escapeHtml(text) {
                    const div = document.createElement('div');
                    div.textContent = text;
                    return div.innerHTML;
                }
                
                function stripHtml(html) {
                    const div = document.createElement('div');
                    div.innerHTML = html;
                    return div.textContent || div.innerText || '';
                }

                async function addNewsArticle() {
                    const title = document.getElementById('articleTitle').value.trim();
                    const content = quillAdd.root.innerHTML.trim();
                    const position = document.getElementById('articlePosition').value;
                    const author_name = document.getElementById('articleAuthor').value.trim();
                    const published_date = document.getElementById('articleDate').value || null;
                    
                    if (!title || content === '<p><br></p>' || !content) {
                        alert('Please enter both title and content');
                        return;
                    }
                    
                    try {
                        const response = await fetch('api/news-articles.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'add', title, content, position, author_name, published_date })
                        });
                        const data = await response.json();
                        if (data.success) {
                            document.getElementById('articleTitle').value = '';
                            document.getElementById('articleAuthor').value = '';
                            document.getElementById('articleDate').value = '';
                            quillAdd.setContents([]);
                            loadNewsArticles();
                        } else {
                            alert(data.error || 'Failed to add article');
                        }
                    } catch (error) {
                        alert('Failed to add article');
                    }
                }

                async function deleteArticle(id) {
                    if (!confirm('Are you sure you want to delete this article?')) return;
                    
                    try {
                        const response = await fetch('api/news-articles.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'delete', id })
                        });
                        const data = await response.json();
                        if (data.success) {
                            loadNewsArticles();
                        } else {
                            alert(data.error || 'Failed to delete article');
                        }
                    } catch (error) {
                        alert('Failed to delete article');
                    }
                }

                let editingArticleId = null;
                
                function editArticle(id) {
                    const article = allArticles.find(a => a.id == id);
                    if (!article) return;
                    
                    editingArticleId = id;
                    document.getElementById('editArticleTitle').value = article.title;
                    document.getElementById('editArticlePosition').value = article.position;
                    document.getElementById('editArticleAuthor').value = article.author_name || '';
                    document.getElementById('editArticleDate').value = article.published_date || '';
                    
                    // Initialize edit Quill if not done
                    if (!quillEdit) {
                        quillEdit = new Quill('#editArticleContentEditor', {
                            theme: 'snow',
                            modules: {
                                toolbar: [
                                    ['bold', 'italic', 'underline'],
                                    [{ 'list': 'ordered'}, { 'list': 'bullet' }],
                                    ['link'],
                                    ['clean']
                                ]
                            }
                        });
                    }
                    
                    // Set content
                    quillEdit.root.innerHTML = article.content;
                    
                    document.getElementById('editArticleModal').style.display = 'flex';
                }
                
                function closeEditModal() {
                    document.getElementById('editArticleModal').style.display = 'none';
                    editingArticleId = null;
                }
                
                async function saveEditedArticle() {
                    if (!editingArticleId) return;
                    
                    const title = document.getElementById('editArticleTitle').value.trim();
                    const content = quillEdit.root.innerHTML.trim();
                    const position = document.getElementById('editArticlePosition').value;
                    const author_name = document.getElementById('editArticleAuthor').value.trim();
                    const published_date = document.getElementById('editArticleDate').value || null;
                    
                    if (!title || content === '<p><br></p>' || !content) {
                        alert('Please enter both title and content');
                        return;
                    }
                    
                    await updateArticle(editingArticleId, title, content, position, author_name, published_date);
                    closeEditModal();
                }

                async function updateArticle(id, title, content, position, author_name, published_date) {
                    try {
                        const response = await fetch('api/news-articles.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'update', id, title, content, position, author_name, published_date })
                        });
                        const data = await response.json();
                        if (data.success) {
                            loadNewsArticles();
                        } else {
                            alert(data.error || 'Failed to update article');
                        }
                    } catch (error) {
                        alert('Failed to update article');
                    }
                }

                function initDragAndDrop() {
                    document.querySelectorAll('.article-card').forEach(card => {
                        card.addEventListener('dragstart', handleDragStart);
                        card.addEventListener('dragend', handleDragEnd);
                        card.addEventListener('dragover', handleDragOver);
                        card.addEventListener('drop', handleDrop);
                    });
                    
                    document.querySelectorAll('.articles-list').forEach(list => {
                        list.addEventListener('dragover', e => e.preventDefault());
                        list.addEventListener('drop', handleListDrop);
                    });
                }

                let draggedElement = null;

                function handleDragStart(e) {
                    draggedElement = this;
                    this.classList.add('dragging');
                    e.dataTransfer.effectAllowed = 'move';
                }

                function handleDragEnd(e) {
                    this.classList.remove('dragging');
                    draggedElement = null;
                }

                function handleDragOver(e) {
                    e.preventDefault();
                    e.dataTransfer.dropEffect = 'move';
                }

                function handleDrop(e) {
                    e.preventDefault();
                    if (draggedElement === this) return;
                    
                    const list = this.parentElement;
                    const cards = Array.from(list.querySelectorAll('.article-card'));
                    const draggedIndex = cards.indexOf(draggedElement);
                    const targetIndex = cards.indexOf(this);
                    
                    if (draggedIndex < targetIndex) {
                        this.parentElement.insertBefore(draggedElement, this.nextSibling);
                    } else {
                        this.parentElement.insertBefore(draggedElement, this);
                    }
                    
                    saveOrder(list.id);
                }

                function handleListDrop(e) {
                    e.preventDefault();
                    if (!draggedElement) return;
                    
                    const sourceListId = draggedElement.dataset.position === 'left' ? 'leftArticlesList' : 'rightArticlesList';
                    const targetListId = this.id;
                    
                    const cards = this.querySelectorAll('.article-card');
                    if (cards.length === 0 || e.target === this) {
                        this.appendChild(draggedElement);
                        const newPosition = this.id === 'leftArticlesList' ? 'left' : 'right';
                        draggedElement.dataset.position = newPosition;
                        
                        if (sourceListId !== targetListId) {
                            saveOrder(sourceListId);
                        }
                        saveOrder(targetListId);
                    }
                }

                async function saveOrder(listId) {
                    const list = document.getElementById(listId);
                    const position = listId === 'leftArticlesList' ? 'left' : 'right';
                    const cards = list.querySelectorAll('.article-card');
                    const articles = Array.from(cards).map((card, index) => ({
                        id: parseInt(card.dataset.id),
                        position: position,
                        display_order: index
                    }));
                    
                    for (const article of articles) {
                        const existing = allArticles.find(a => a.id === article.id);
                        if (existing && existing.position !== article.position) {
                            await fetch('api/news-articles.php', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ 
                                    action: 'update', 
                                    id: article.id, 
                                    title: existing.title,
                                    content: existing.content,
                                    position: article.position 
                                })
                            });
                        }
                    }
                    
                    try {
                        await fetch('api/news-articles.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'reorder', articles })
                        });
                        loadNewsArticles();
                    } catch (error) {
                        console.error('Failed to save order:', error);
                    }
                }

                if (document.readyState === 'loading') {
                    document.addEventListener('DOMContentLoaded', loadNewsArticles);
                } else {
                    loadNewsArticles();
                }
                </script>
                
                <!-- Edit Article Modal -->
                <div id="editArticleModal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center;">
                    <div style="background: white; border-radius: 12px; max-width: 600px; width: 90%; max-height: 90vh; overflow-y: auto; padding: 24px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                            <h3 style="margin: 0;">Edit Article</h3>
                            <button onclick="closeEditModal()" style="background: none; border: none; font-size: 24px; cursor: pointer; color: #65676b;">&times;</button>
                        </div>
                        <div class="form-group">
                            <label for="editArticleTitle">Title</label>
                            <input type="text" id="editArticleTitle" placeholder="Enter article title...">
                        </div>
                        <div class="form-group">
                            <label>Content</label>
                            <div id="editArticleContentEditor" style="height: 200px; background: white;"></div>
                        </div>
                        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px;">
                            <div class="form-group">
                                <label for="editArticleAuthor">Author/Writer</label>
                                <input type="text" id="editArticleAuthor" placeholder="Author name...">
                            </div>
                            <div class="form-group">
                                <label for="editArticleDate">Published Date</label>
                                <input type="date" id="editArticleDate">
                            </div>
                            <div class="form-group">
                                <label for="editArticlePosition">Position</label>
                                <select id="editArticlePosition">
                                    <option value="left">Left Sidebar</option>
                                    <option value="right">Right Sidebar</option>
                                </select>
                            </div>
                        </div>
                        <div style="display: flex; gap: 10px; justify-content: flex-end; margin-top: 20px;">
                            <button type="button" class="btn btn-secondary" onclick="closeEditModal()">Cancel</button>
                            <button type="button" class="btn btn-primary" onclick="saveEditedArticle()">Save Changes</button>
                        </div>
                    </div>
                </div>

            <?php elseif ($activeTab === 'products'): ?>
                <h2>Printify Product Sync</h2>
                <p style="color: #65676b; margin-bottom: 20px;">
                    Use the button below to sync products from your Printify store.
                </p>
                
                <?php if (isset($_GET['product_updated'])): ?>
                    <div class="alert alert-success">Product updated successfully!</div>
                <?php endif; ?>
                <?php if (isset($_GET['product_deleted'])): ?>
                    <div class="alert alert-success">Product deleted successfully!</div>
                <?php endif; ?>
                <?php if (isset($_GET['synced'])): ?>
                    <div class="alert alert-success">Synced <?php echo intval($_GET['synced']); ?> products from Printify!</div>
                <?php endif; ?>
                <?php if (isset($_GET['sync_error'])): ?>
                    <div class="alert alert-error" style="background: #fee2e2; color: #dc2626; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                        <strong>Sync failed:</strong> <?php echo h($_GET['error_msg'] ?? 'Please check your Printify API key.'); ?>
                    </div>
                <?php endif; ?>
                <?php if (isset($_GET['cleared'])): ?>
                    <div class="alert alert-success">Cleared stuck publishing status for <?php echo intval($_GET['cleared']); ?> of <?php echo intval($_GET['total']); ?> products in Printify!</div>
                <?php endif; ?>
                <?php if (isset($_GET['clear_error'])): ?>
                    <div class="alert alert-error" style="background: #fee2e2; color: #dc2626; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                        <strong>Clear failed:</strong> <?php echo h($_GET['error_msg'] ?? 'Unknown error'); ?>
                    </div>
                <?php endif; ?>
                <?php if (isset($_GET['published'])): ?>
                    <?php 
                    $publishedCount = intval($_GET['published']);
                    $skippedCount = intval($_GET['skipped'] ?? 0);
                    $totalCount = intval($_GET['total']);
                    ?>
                    <div class="alert alert-success">
                        Processed <?php echo $totalCount; ?> products: 
                        <?php echo $publishedCount; ?> marked as published
                        <?php if ($skippedCount > 0): ?>
                            , <?php echo $skippedCount; ?> skipped (already published or not in Printify's publishing queue)
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
                <?php if (isset($_GET['publish_error'])): ?>
                    <div class="alert alert-error" style="background: #fee2e2; color: #dc2626; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                        <strong>Publish failed:</strong> <?php echo h($_GET['error_msg'] ?? 'Unknown error'); ?>
                    </div>
                <?php endif; ?>

                <div style="background: #e8f4fd; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #b3d7f5;">
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                        <div>
                            <strong>🧪 Test Custom Order Payload</strong>
                            <p style="margin: 5px 0 0 0; color: #65676b; font-size: 13px;">Check what data would be sent to Printify for recent custom orders</p>
                        </div>
                        <button type="button" class="btn btn-secondary" onclick="testPrintifyPayload()" style="padding: 10px 20px;">
                            View Test Payload
                        </button>
                    </div>
                </div>

                <div style="background: #f0f2f5; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px;">
                        <div>
                            <strong>Last Sync:</strong>
                            <?php if ($lastSyncTime): ?>
                                <span style="color: #65676b;">
                                    <?php echo date('M j, Y g:i A', strtotime($lastSyncTime)); ?>
                                    (<?php 
                                        $hoursAgo = round((time() - strtotime($lastSyncTime)) / 3600, 1);
                                        echo $hoursAgo < 1 ? 'less than 1 hour ago' : $hoursAgo . ' hours ago';
                                    ?>)
                                </span>
                            <?php else: ?>
                                <span style="color: #65676b;">Never synced</span>
                            <?php endif; ?>
                        </div>
                        <form method="POST" style="margin: 0;">
                            <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                            <input type="hidden" name="action" value="sync_printify">
                            <button type="submit" class="btn btn-primary" style="padding: 12px 24px;">
                                Sync Products Now
                            </button>
                        </form>
                    </div>
                </div>
                
                <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #ffc107;">
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px;">
                        <div style="flex: 1; min-width: 250px;">
                            <strong>Printify Publishing Status</strong>
                            <p style="margin: 5px 0 0 0; color: #856404; font-size: 13px;">
                                Fix products stuck in "Publishing" status or notify Printify when products are live on your site.
                            </p>
                        </div>
                        <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                            <form method="POST" style="margin: 0;" onsubmit="return confirm('This will clear the publishing status for all products stuck in Printify. Continue?');">
                                <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                                <input type="hidden" name="action" value="clear_stuck_publishing">
                                <button type="submit" class="btn" style="padding: 10px 16px; background: #dc3545; color: white; border: none; border-radius: 6px; cursor: pointer;">
                                    Clear Stuck Status
                                </button>
                            </form>
                            <form method="POST" style="margin: 0;" onsubmit="return confirm('This will mark all active products as published in Printify, linking them to your site. Continue?');">
                                <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                                <input type="hidden" name="action" value="mark_published">
                                <button type="submit" class="btn" style="padding: 10px 16px; background: #28a745; color: white; border: none; border-radius: 6px; cursor: pointer;">
                                    Mark All Published
                                </button>
                            </form>
                        </div>
                    </div>
                </div>

                <?php
                // Get feed posts
                $feedPostsStmt = $pdo->query("
                    SELECT fpp.id as feed_post_id, fpp.created_at, fpp.variant_id,
                           pp.id as product_id, pp.name, pp.thumbnail_url,
                           pv.color as variant_color, pv.image_url as variant_image
                    FROM feed_product_posts fpp
                    JOIN pod_products pp ON fpp.product_id = pp.id
                    LEFT JOIN pod_product_variants pv ON fpp.variant_id = pv.id
                    ORDER BY fpp.created_at DESC
                ");
                $feedPosts = $feedPostsStmt->fetchAll();
                ?>
                
                <h3>Products in Feed (<?php echo count($feedPosts); ?>)</h3>
                <p style="color: #65676b; margin-bottom: 15px;">Products currently shown in the community feed. Click "Remove" to delete from feed.</p>
                <?php if (empty($feedPosts)): ?>
                    <div style="background: #f8f9fa; padding: 30px; border-radius: 8px; text-align: center; color: #65676b; margin-bottom: 30px;">
                        No products posted to feed yet. Use "Post to Feed" button below to add products.
                    </div>
                <?php else: ?>
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px; margin-bottom: 30px;">
                        <?php foreach ($feedPosts as $fp): 
                            $displayImage = $fp['variant_image'] ?: $fp['thumbnail_url'];
                        ?>
                            <div style="border: 1px solid #e4e6e9; border-radius: 8px; padding: 12px; text-align: center; background: white;">
                                <img src="<?php echo h($displayImage); ?>" alt="<?php echo h($fp['name']); ?>" 
                                     style="max-width: 100%; height: 100px; object-fit: contain; margin-bottom: 8px;">
                                <h4 style="margin: 0 0 4px 0; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;"><?php echo h($fp['name']); ?></h4>
                                <?php if ($fp['variant_color']): ?>
                                    <p style="margin: 0 0 8px 0; font-size: 11px; color: #65676b;">Color: <?php echo h($fp['variant_color']); ?></p>
                                <?php endif; ?>
                                <button onclick="removeFromFeed(<?php echo $fp['feed_post_id']; ?>)" 
                                        style="padding: 5px 12px; background: #e41e3f; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 11px;">
                                    Remove from Feed
                                </button>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                
                <hr style="border: none; border-top: 1px solid #e4e6e9; margin: 30px 0;">
                
                <?php
                $podProducts = getPodProducts();
                ?>
                <h3>All Products (<?php echo count($podProducts); ?>)</h3>
                <?php if (empty($podProducts)): ?>
                    <p style="text-align: center; padding: 40px; color: #65676b;">No products synced yet. Click "Sync Products Now" to fetch from Printify.</p>
                <?php else: ?>
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px;">
                        <?php foreach ($podProducts as $product): 
                            $isCustomizable = !empty($product['is_customizable']);
                        ?>
                            <div style="border: 1px solid <?php echo $isCustomizable ? '#ffc107' : '#e4e6e9'; ?>; border-radius: 8px; padding: 15px; text-align: center; <?php echo $isCustomizable ? 'background: #fffbeb;' : ''; ?>">
                                <img src="<?php echo h($product['thumbnail_url']); ?>" alt="<?php echo h($product['name']); ?>" 
                                     style="max-width: 100%; height: 150px; object-fit: contain; margin-bottom: 10px;">
                                <h4 style="margin: 0 0 5px 0; font-size: 14px;"><?php echo h($product['name']); ?></h4>
                                <p style="margin: 0; color: #1877f2; font-weight: 600;">
                                    $<?php echo number_format(floatval($product['min_price'] ?? 0), 2); ?>
                                    <?php if (($product['min_price'] ?? 0) != ($product['max_price'] ?? 0)): ?>
                                        - $<?php echo number_format(floatval($product['max_price'] ?? 0), 2); ?>
                                    <?php endif; ?>
                                </p>
                                <p style="margin: 5px 0 0 0; color: #65676b; font-size: 12px;">
                                    <?php echo count($product['variants'] ?? []); ?> variant(s)
                                </p>
                                <label style="display: flex; align-items: center; justify-content: center; gap: 6px; margin-top: 10px; cursor: pointer; padding: 6px; background: <?php echo $isCustomizable ? '#ffc107' : '#f0f2f5'; ?>; border-radius: 4px;">
                                    <input type="checkbox" 
                                           id="customizable_<?php echo $product['id']; ?>"
                                           <?php echo $isCustomizable ? 'checked' : ''; ?>
                                           onchange="toggleCustomizable(<?php echo $product['id']; ?>, this.checked)"
                                           style="width: 16px; height: 16px; cursor: pointer;">
                                    <span style="font-size: 12px; font-weight: 600; color: <?php echo $isCustomizable ? '#856404' : '#65676b'; ?>;">Customizable</span>
                                </label>
                                <div style="margin-top: 10px; display: flex; gap: 8px; justify-content: center; flex-wrap: wrap;">
                                    <button onclick="postProductToFeed(<?php echo $product['id']; ?>, '<?php echo h(addslashes($product['name'])); ?>')" 
                                            style="padding: 6px 12px; background: #42b72a; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">
                                        Post to Feed
                                    </button>
                                    <button onclick="editProduct(<?php echo $product['id']; ?>)" 
                                            style="padding: 6px 12px; background: #1877f2; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">
                                        Edit
                                    </button>
                                    <button onclick="deleteProduct(<?php echo $product['id']; ?>, '<?php echo h(addslashes($product['name'])); ?>')" 
                                            style="padding: 6px 12px; background: #e41e3f; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">
                                        Delete
                                    </button>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                
                <script>
                // Toggle customizable status
                function toggleCustomizable(productId, isCustomizable) {
                    const formData = new FormData();
                    formData.append('action', 'toggle_customizable');
                    formData.append('id', productId);
                    formData.append('is_customizable', isCustomizable ? '1' : '0');
                    
                    fetch('api/pod-admin.php', {
                        method: 'POST',
                        body: formData
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            window.location.reload();
                        } else {
                            alert(data.error || 'Failed to update');
                            document.getElementById('customizable_' + productId).checked = !isCustomizable;
                        }
                    })
                    .catch(err => {
                        console.error('Toggle error:', err);
                        alert('Failed to update. Please try again.');
                        document.getElementById('customizable_' + productId).checked = !isCustomizable;
                    });
                }
                
                // Product Edit/Delete Functions for Products Tab
                function editProduct(productId) {
                    fetch('api/pod-admin.php?action=get&id=' + productId)
                        .then(r => r.json())
                        .then(data => {
                            if (data.success) {
                                const product = data.product;
                                document.getElementById('editProductId').value = product.id;
                                document.getElementById('editProductName').value = product.name || '';
                                document.getElementById('editProductDescription').value = product.description || '';
                                
                                // Show custom mockup preview if exists
                                if (product.custom_mockup_url) {
                                    showMockupPreview(product.custom_mockup_url);
                                } else {
                                    hideMockupPreview();
                                }
                                
                                if (product.feed_mockup_url) {
                                    showFeedMockupPreview(product.feed_mockup_url);
                                } else {
                                    hideFeedMockupPreview();
                                }
                                
                                if (product.sample_template_url) {
                                    showSampleTemplatePreview(product.sample_template_url);
                                } else {
                                    hideSampleTemplatePreview();
                                }
                                
                                // Populate mockup picker gallery
                                populateMockupGallery(product.all_images || [], product.feed_mockup_url);
                                
                                // Populate customization fields
                                populateCustomizationFields(product);
                                
                                document.getElementById('editProductModal').style.display = 'flex';
                                
                                // Load variant mockups for customizable products
                                if (product.is_customizable) {
                                    setTimeout(loadVariantMockups, 100);
                                }
                            } else {
                                alert(data.error || 'Failed to load product');
                            }
                        })
                        .catch(err => {
                            console.error('Edit product error:', err);
                            alert('Failed to load product. Please try again.');
                        });
                }
                
                function populateMockupGallery(images, currentFeedMockup) {
                    const gallery = document.getElementById('mockupPickerGallery');
                    if (!gallery) return;
                    
                    if (!images || images.length === 0) {
                        gallery.innerHTML = '<p style="grid-column: 1/-1; text-align: center; color: #65676b;">No images available</p>';
                        return;
                    }
                    
                    gallery.innerHTML = images.map(img => `
                        <div onclick="selectFeedMockup('${img.replace(/'/g, "\\'")}')" 
                             style="cursor: pointer; border: 3px solid ${currentFeedMockup === img ? '#ffc107' : 'transparent'}; border-radius: 8px; overflow: hidden; transition: all 0.2s;"
                             onmouseover="this.style.borderColor='#1877f2'"
                             onmouseout="this.style.borderColor='${currentFeedMockup === img ? '#ffc107' : 'transparent'}'">
                            <img src="${img}" alt="Mockup option" style="width: 100%; height: 100px; object-fit: cover; display: block;">
                        </div>
                    `).join('');
                }
                
                function selectFeedMockup(imageUrl) {
                    const productId = document.getElementById('editProductId').value;
                    if (!productId) {
                        alert('Product not loaded');
                        return;
                    }
                    
                    const formData = new FormData();
                    formData.append('action', 'set_feed_mockup_url');
                    formData.append('id', productId);
                    formData.append('url', imageUrl);
                    
                    fetch('api/pod-admin.php', {
                        method: 'POST',
                        body: formData
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            showFeedMockupPreview(imageUrl);
                            // Update gallery to show selected
                            document.querySelectorAll('#mockupPickerGallery > div').forEach(div => {
                                const img = div.querySelector('img');
                                if (img && img.src === imageUrl) {
                                    div.style.borderColor = '#ffc107';
                                } else {
                                    div.style.borderColor = 'transparent';
                                }
                            });
                            alert('Feed mockup updated! Refresh the feed to see changes.');
                        } else {
                            alert(data.error || 'Failed to set feed mockup');
                        }
                    })
                    .catch(err => {
                        console.error('Set feed mockup error:', err);
                        alert('Failed to set feed mockup');
                    });
                }
                
                function closeEditProductModal() {
                    document.getElementById('editProductModal').style.display = 'none';
                }
                
                function loadVariantMockups() {
                    const productId = document.getElementById('editProductId').value;
                    const grid = document.getElementById('variantMockupsGrid');
                    
                    if (!productId) {
                        grid.innerHTML = '<p style="color: #718096; font-size: 11px; grid-column: 1/-1; text-align: center;">Save product first to manage variants.</p>';
                        return;
                    }
                    
                    grid.innerHTML = '<p style="color: #718096; font-size: 11px; grid-column: 1/-1; text-align: center; padding: 20px;">Loading variants...</p>';
                    
                    fetch('api/pod-admin.php?action=get_variants&product_id=' + productId)
                        .then(r => r.json())
                        .then(data => {
                            if (data.success && data.variants && data.variants.length > 0) {
                                grid.innerHTML = '';
                                data.variants.forEach(variant => {
                                    const card = document.createElement('div');
                                    card.style.cssText = 'background: white; border-radius: 6px; padding: 8px; text-align: center; border: 1px solid #e2e8f0;';
                                    
                                    const colorName = variant.color || '';
                                    const sizeName = variant.size || '';
                                    const variantLabel = colorName + (colorName && sizeName ? ' - ' : '') + sizeName || 'Variant';
                                    const hasBlankMockup = variant.blank_mockup_url && variant.blank_mockup_url.trim() !== '';
                                    
                                    const mockupSrc = hasBlankMockup ? (variant.blank_mockup_url.startsWith('/') || variant.blank_mockup_url.startsWith('http') ? variant.blank_mockup_url : '/' + variant.blank_mockup_url) : '';
                                    card.innerHTML = `
                                        <p style="font-size: 11px; font-weight: 600; color: #2d3748; margin: 0 0 6px 0;">${variantLabel}</p>
                                        <div id="variantMockupPreview_${variant.id}" style="width: 80px; height: 80px; margin: 0 auto 8px; border: 2px dashed #cbd5e0; border-radius: 4px; display: flex; align-items: center; justify-content: center; overflow: hidden; background: #f7fafc;">
                                            ${hasBlankMockup 
                                                ? `<img src="${mockupSrc}" style="max-width: 100%; max-height: 100%; object-fit: contain;">` 
                                                : '<span style="font-size: 24px; color: #a0aec0;">+</span>'}
                                        </div>
                                        <input type="file" id="variantMockupInput_${variant.id}" accept="image/*" style="display: none;" onchange="uploadVariantMockup(${variant.id}, this)">
                                        <div style="display: flex; gap: 4px; justify-content: center;">
                                            <button type="button" onclick="document.getElementById('variantMockupInput_${variant.id}').click()" 
                                                style="padding: 3px 6px; font-size: 9px; background: #4299e1; color: white; border: none; border-radius: 3px; cursor: pointer;">Upload</button>
                                            ${hasBlankMockup ? `<button type="button" onclick="removeVariantMockup(${variant.id})" 
                                                style="padding: 3px 6px; font-size: 9px; background: #e53e3e; color: white; border: none; border-radius: 3px; cursor: pointer;">×</button>` : ''}
                                        </div>
                                    `;
                                    grid.appendChild(card);
                                });
                            } else {
                                grid.innerHTML = '<p style="color: #718096; font-size: 11px; grid-column: 1/-1; text-align: center;">No variants found for this product.</p>';
                            }
                        })
                        .catch(err => {
                            console.error('Load variants error:', err);
                            grid.innerHTML = '<p style="color: #e53e3e; font-size: 11px; grid-column: 1/-1; text-align: center;">Failed to load variants.</p>';
                        });
                }
                
                function uploadVariantMockup(variantId, input) {
                    if (!input.files || !input.files[0]) return;
                    
                    const formData = new FormData();
                    formData.append('action', 'upload_variant_blank_mockup');
                    formData.append('variant_id', variantId);
                    formData.append('blank_mockup', input.files[0]);
                    
                    const preview = document.getElementById('variantMockupPreview_' + variantId);
                    preview.innerHTML = '<span style="font-size: 10px; color: #718096;">Uploading...</span>';
                    
                    fetch('api/pod-admin.php', {
                        method: 'POST',
                        body: formData
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            loadVariantMockups();
                        } else {
                            alert(data.error || 'Failed to upload variant mockup');
                            loadVariantMockups();
                        }
                    })
                    .catch(err => {
                        console.error('Upload variant mockup error:', err);
                        alert('Failed to upload variant mockup');
                        loadVariantMockups();
                    });
                }
                
                function removeVariantMockup(variantId) {
                    if (!confirm('Remove this variant mockup?')) return;
                    
                    const formData = new FormData();
                    formData.append('action', 'remove_variant_blank_mockup');
                    formData.append('variant_id', variantId);
                    
                    fetch('api/pod-admin.php', {
                        method: 'POST',
                        body: formData
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            loadVariantMockups();
                        } else {
                            alert(data.error || 'Failed to remove variant mockup');
                        }
                    })
                    .catch(err => {
                        console.error('Remove variant mockup error:', err);
                        alert('Failed to remove variant mockup');
                    });
                }
                
                function saveProductEdit() {
                    const id = document.getElementById('editProductId').value;
                    const name = document.getElementById('editProductName').value;
                    const description = document.getElementById('editProductDescription').value;
                    
                    // Include customization settings if the section is visible
                    const customizationSection = document.getElementById('customizationSettingsSection');
                    const isCustomizable = customizationSection && customizationSection.style.display !== 'none';
                    
                    let payload = {action: 'update', id: id, name: name, description: description};
                    
                    if (isCustomizable) {
                        payload.customization = getCustomizationSettings();
                    }
                    
                    fetch('api/pod-admin.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(payload)
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            closeEditProductModal();
                            window.location.href = 'admin.php?tab=products&product_updated=1';
                        } else {
                            alert(data.error || 'Failed to update product');
                        }
                    })
                    .catch(err => {
                        console.error('Save product error:', err);
                        alert('Failed to save product. Please try again.');
                    });
                }
                
                function deleteProduct(productId, productName) {
                    if (!confirm('Delete "' + productName + '" from the shop? This will not remove it from Printify.')) return;
                    
                    fetch('api/pod-admin.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({action: 'delete', id: productId})
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            window.location.href = 'admin.php?tab=products&product_deleted=1';
                        } else {
                            alert(data.error || 'Failed to delete product');
                        }
                    })
                    .catch(err => {
                        console.error('Delete product error:', err);
                        alert('Failed to delete product. Please try again.');
                    });
                }
                
                let currentPostProductId = null;
                let currentPostProductName = '';
                
                let selectedVariantId = null;
                
                function postProductToFeed(productId, productName) {
                    currentPostProductId = productId;
                    currentPostProductName = productName;
                    selectedVariantId = null;
                    
                    // Fetch variants for this product
                    fetch('api/pod-products.php?action=get&id=' + productId)
                        .then(r => r.json())
                        .then(data => {
                            if (data.success && data.product) {
                                const product = data.product;
                                const variants = product.variants || [];
                                const gallery = document.getElementById('feedVariantGallery');
                                
                                // Collect all unique images
                                let images = [];
                                const seenUrls = new Set();
                                
                                // FIRST: Add feed mockup if set (user's hand-picked image for feed)
                                if (product.feed_mockup_url) {
                                    images.push({id: 'feed_mockup', url: product.feed_mockup_url, label: '⭐ Feed Mockup', highlight: true});
                                    seenUrls.add(product.feed_mockup_url);
                                }
                                
                                // Add default thumbnail if different from feed mockup
                                if (product.thumbnail_url && !seenUrls.has(product.thumbnail_url)) {
                                    images.push({id: '', url: product.thumbnail_url, label: 'Default'});
                                    seenUrls.add(product.thumbnail_url);
                                }
                                
                                // Group variants by unique image URL
                                variants.forEach(v => {
                                    if (v.image_url && !seenUrls.has(v.image_url)) {
                                        seenUrls.add(v.image_url);
                                        images.push({id: v.id, url: v.image_url, label: v.color || 'Variant'});
                                    }
                                });
                                
                                // Build image gallery - highlight feed mockup with golden border
                                gallery.innerHTML = images.map(img => `
                                    <div onclick="selectFeedVariant('${img.id}', this)" 
                                         style="cursor: pointer; border: 3px solid ${img.highlight ? '#ffc107' : 'transparent'}; border-radius: 8px; overflow: hidden; transition: all 0.2s; text-align: center; ${img.highlight ? 'background: #fffbeb;' : ''}"
                                         data-variant-id="${img.id}">
                                        <img src="${img.url}" alt="${img.label}" style="width: 100%; height: 80px; object-fit: cover; display: block;">
                                        <p style="margin: 4px 0 0 0; font-size: 10px; color: ${img.highlight ? '#856404' : '#65676b'}; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-weight: ${img.highlight ? '600' : 'normal'};">${img.label}</p>
                                    </div>
                                `).join('');
                                
                                // Select first image by default (feed mockup if exists)
                                const defaultId = product.feed_mockup_url ? 'feed_mockup' : '';
                                if (gallery.firstElementChild) {
                                    selectFeedVariant(defaultId, gallery.firstElementChild);
                                }
                                
                                document.getElementById('feedProductName').textContent = productName;
                                document.getElementById('postToFeedModal').style.display = 'flex';
                            } else {
                                alert('Failed to load product variants');
                            }
                        })
                        .catch(err => {
                            console.error('Error loading variants:', err);
                            alert('Failed to load product variants');
                        });
                }
                
                function selectFeedVariant(variantId, element) {
                    // Store null for feed_mockup or empty string (use product's feed_mockup_url)
                    // Store actual variant ID for variant selections
                    if (variantId === 'feed_mockup' || variantId === '') {
                        selectedVariantId = null;
                    } else {
                        selectedVariantId = variantId;
                    }
                    
                    // Update selected styling - remove all borders first
                    document.querySelectorAll('#feedVariantGallery > div').forEach(div => {
                        const isHighlighted = div.querySelector('p')?.style.fontWeight === '600';
                        div.style.borderColor = isHighlighted ? '#ffc107' : 'transparent';
                    });
                    // Add blue selection border to clicked element
                    if (element) {
                        element.style.borderColor = '#1877f2';
                    }
                }
                
                function closePostToFeedModal() {
                    document.getElementById('postToFeedModal').style.display = 'none';
                    currentPostProductId = null;
                }
                
                function confirmPostToFeed() {
                    if (!currentPostProductId) return;
                    
                    // selectedVariantId is already null for feed_mockup/default, or actual variant ID
                    // Pass it directly to the API
                    
                    fetch('api/feed-products.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            action: 'post', 
                            product_id: currentPostProductId,
                            variant_id: selectedVariantId
                        })
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            closePostToFeedModal();
                            alert('"' + currentPostProductName + '" has been posted to the feed!');
                            window.location.reload();
                        } else {
                            alert(data.error || 'Failed to post product to feed');
                        }
                    })
                    .catch(err => {
                        console.error('Post to feed error:', err);
                        alert('Failed to post product to feed. Please try again.');
                    });
                }
                
                function testPrintifyPayload() {
                    fetch('api/debug-printify-order.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({get_recent_orders: true})
                    })
                    .then(r => r.json())
                    .then(data => {
                        let modal = document.getElementById('printifyTestModal');
                        if (!modal) {
                            modal = document.createElement('div');
                            modal.id = 'printifyTestModal';
                            modal.innerHTML = `
                                <div style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.6); z-index: 9999; display: flex; align-items: center; justify-content: center;">
                                    <div style="background: white; padding: 25px; border-radius: 12px; max-width: 800px; width: 90%; max-height: 80vh; overflow-y: auto;">
                                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                                            <h3 style="margin: 0;">Printify Order Test</h3>
                                            <button onclick="document.getElementById('printifyTestModal').remove()" style="border: none; background: none; font-size: 24px; cursor: pointer;">&times;</button>
                                        </div>
                                        <div id="printifyTestContent"></div>
                                    </div>
                                </div>
                            `;
                            document.body.appendChild(modal);
                        }
                        
                        let content = document.getElementById('printifyTestContent');
                        if (data.recent_orders && data.recent_orders.length > 0) {
                            let html = '<p style="color: #65676b; margin-bottom: 15px;">Recent custom orders that would include designs:</p>';
                            data.recent_orders.forEach(order => {
                                const hasBlueprint = order.blueprint_id && order.print_provider_id;
                                const statusColor = hasBlueprint ? '#059669' : '#dc2626';
                                const statusText = hasBlueprint ? '✓ Ready' : '⚠ Missing IDs';
                                html += `
                                    <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 10px; border-left: 4px solid ${statusColor};">
                                        <div style="display: flex; justify-content: space-between; align-items: start; gap: 15px;">
                                            <div style="flex: 1;">
                                                <strong>${order.product_name || 'Unknown Product'}</strong>
                                                <span style="background: ${statusColor}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin-left: 10px;">${statusText}</span>
                                                <p style="margin: 8px 0 0 0; font-size: 13px; color: #65676b;">Order: ${order.custom_order_id}</p>
                                                <p style="margin: 4px 0 0 0; font-size: 13px;">Blueprint: ${order.blueprint_id || 'NULL'} | Provider: ${order.print_provider_id || 'NULL'}</p>
                                                <p style="margin: 4px 0 0 0; font-size: 12px; color: #0066cc; word-break: break-all;">Design: ${order.print_url || 'None'}</p>
                                            </div>
                                            ${order.mockup_url ? '<img src="' + order.mockup_url + '" style="width: 80px; height: 80px; object-fit: cover; border-radius: 6px;">' : ''}
                                        </div>
                                    </div>
                                `;
                            });
                            if (!data.recent_orders.some(o => o.blueprint_id && o.print_provider_id)) {
                                html += '<p style="background: #fef2f2; padding: 12px; border-radius: 6px; color: #dc2626; margin-top: 15px;"><strong>Action needed:</strong> Click "Sync Products Now" to fetch blueprint_id and print_provider_id for your products.</p>';
                            }
                            content.innerHTML = html;
                        } else {
                            content.innerHTML = '<p style="color: #65676b; text-align: center; padding: 30px;">No recent custom orders found. Create a test order to see the payload.</p>';
                        }
                        modal.style.display = 'block';
                    })
                    .catch(err => {
                        console.error('Test error:', err);
                        alert('Failed to test payload: ' + err.message);
                    });
                }

                function removeFromFeed(feedPostId) {
                    if (!confirm('Remove this product from the community feed?')) return;
                    
                    fetch('api/feed-products.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({action: 'remove', feed_post_id: feedPostId})
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            window.location.reload();
                        } else {
                            alert(data.error || 'Failed to remove from feed');
                        }
                    })
                    .catch(err => {
                        console.error('Remove from feed error:', err);
                        alert('Failed to remove from feed. Please try again.');
                    });
                }
                </script>
                
                <!-- Post to Feed Modal -->
                <div id="postToFeedModal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; align-items: center; justify-content: center;">
                    <div style="background: white; padding: 30px; border-radius: 12px; max-width: 600px; width: 90%;">
                        <h3 style="margin: 0 0 20px 0;">Post to Community Feed</h3>
                        <p style="margin: 0 0 15px 0; color: #65676b;">Posting: <strong id="feedProductName"></strong></p>
                        <div style="margin-bottom: 20px;">
                            <label style="display: block; margin-bottom: 8px; font-weight: 600;">Click an image to select it for the feed:</label>
                            <div id="feedVariantGallery" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(90px, 1fr)); gap: 10px; max-height: 250px; overflow-y: auto; padding: 10px; background: #f8f9fa; border-radius: 8px; border: 1px solid #e4e6e9;">
                                <p style="grid-column: 1/-1; text-align: center; color: #65676b;">Loading images...</p>
                            </div>
                            <p style="font-size: 12px; color: #65676b; margin-top: 8px;">The selected image will appear in the community feed</p>
                        </div>
                        <div style="display: flex; gap: 10px; justify-content: flex-end;">
                            <button onclick="closePostToFeedModal()" style="padding: 10px 20px; border: 1px solid #e4e6e9; background: white; border-radius: 6px; cursor: pointer;">Cancel</button>
                            <button onclick="confirmPostToFeed()" style="padding: 10px 20px; background: #42b72a; color: white; border: none; border-radius: 6px; cursor: pointer;">Post to Feed</button>
                        </div>
                    </div>
                </div>

            <?php elseif ($activeTab === 'custom-pod'): ?>
                <?php
                // Get customizable products
                $customizableProducts = [];
                try {
                    $stmt = $pdo->query("
                        SELECT p.*, 
                               (SELECT MIN(retail_price) FROM pod_product_variants WHERE pod_product_id = p.id) as min_price,
                               (SELECT MAX(retail_price) FROM pod_product_variants WHERE pod_product_id = p.id) as max_price
                        FROM pod_products p
                        WHERE p.is_active = TRUE AND p.is_customizable = TRUE
                        ORDER BY p.name ASC
                    ");
                    $customizableProducts = $stmt->fetchAll();
                } catch (Exception $e) {
                    error_log('Get customizable products error: ' . $e->getMessage());
                }
                ?>
                
                <h2>Customizable POD Products (<?php echo count($customizableProducts); ?>)</h2>
                <p style="color: #65676b; margin-bottom: 20px;">
                    Products marked as customizable in the POD Products tab appear here. Customers can personalize these with their own text, images, or designs.
                </p>
                
                <div style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 15px; margin-bottom: 20px;">
                    <strong style="color: #856404;">💡 How to add products here</strong>
                    <p style="margin: 8px 0 0 0; font-size: 13px; color: #856404;">
                        Go to the <a href="?tab=products" style="color: #1877f2; font-weight: 600;">POD Products tab</a> and check the "Customizable" checkbox on any product you want to appear here.
                    </p>
                </div>
                
                <?php if (empty($customizableProducts)): ?>
                    <div style="background: #f8f9fa; border-radius: 8px; padding: 30px; text-align: center;">
                        <div style="font-size: 48px; margin-bottom: 15px;">🎨</div>
                        <h3 style="margin: 0 0 10px 0;">No Customizable Products Yet</h3>
                        <p style="color: #65676b; margin: 0;">
                            Mark products as "Customizable" in the POD Products tab to see them here.
                        </p>
                    </div>
                <?php else: ?>
                    <div style="display: flex; flex-direction: column; gap: 20px;">
                        <?php foreach ($customizableProducts as $product): ?>
                            <div style="border: 2px solid #ffc107; border-radius: 8px; padding: 20px; background: #fffbeb;">
                                <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                                    <?php 
                                    $isRound = ($product['product_shape'] ?? 'flat') === 'round';
                                    $shapeIcon = $isRound ? '🥤' : '👕';
                                    $shapeLabel = $isRound ? 'Round/Cylindrical' : 'Flat Product';
                                    $shapeBg = $isRound ? '#e8f4fc' : '#f5e6ff';
                                    $shapeColor = $isRound ? '#0066cc' : '#6b21a8';
                                    ?>
                                    <!-- Product Image & Info -->
                                    <div style="flex: 0 0 180px; text-align: center;">
                                        <div style="display: flex; gap: 6px; justify-content: center; margin-bottom: 10px;">
                                            <div style="background: #ffc107; color: #856404; padding: 4px 10px; border-radius: 12px; font-size: 11px; font-weight: 600;">
                                                CUSTOMIZABLE
                                            </div>
                                            <div style="background: <?php echo $shapeBg; ?>; color: <?php echo $shapeColor; ?>; padding: 4px 10px; border-radius: 12px; font-size: 11px; font-weight: 600;">
                                                <?php echo $shapeIcon; ?> <?php echo $shapeLabel; ?>
                                            </div>
                                        </div>
                                        <img src="<?php echo h($product['thumbnail_url']); ?>" alt="<?php echo h($product['name']); ?>" 
                                             style="max-width: 100%; height: 140px; object-fit: contain; margin-bottom: 10px;">
                                        <h4 style="margin: 0 0 5px 0; font-size: 14px;"><?php echo h($product['name']); ?></h4>
                                        <p style="margin: 0; color: #1877f2; font-weight: 600;">
                                            $<?php echo number_format(floatval($product['min_price'] ?? 0), 2); ?>
                                            <?php if (($product['min_price'] ?? 0) != ($product['max_price'] ?? 0)): ?>
                                                - $<?php echo number_format(floatval($product['max_price'] ?? 0), 2); ?>
                                            <?php endif; ?>
                                        </p>
                                    </div>
                                    
                                    <!-- Template & Mockup Uploads -->
                                    <div style="flex: 1; min-width: 250px;">
                                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px;">
                                            <!-- Template Upload -->
                                            <div>
                                                <label style="display: block; font-weight: 600; font-size: 12px; margin-bottom: 5px; color: #333;">Template Image</label>
                                                <?php if (!empty($product['template_url'])): ?>
                                                    <div style="position: relative; display: inline-block;">
                                                        <img src="/<?php echo ltrim(h($product['template_url']), '/'); ?>" style="max-width: 100px; max-height: 80px; border-radius: 4px; border: 1px solid #ddd;">
                                                        <button onclick="removeCustomPodFile(<?php echo $product['id']; ?>, 'template')" 
                                                                style="position: absolute; top: -8px; right: -8px; background: #e41e3f; color: white; border: none; border-radius: 50%; width: 20px; height: 20px; cursor: pointer; font-size: 12px;">×</button>
                                                    </div>
                                                <?php else: ?>
                                                    <div style="border: 2px dashed #ccc; border-radius: 6px; padding: 15px; text-align: center; cursor: pointer; background: white;"
                                                         onclick="document.getElementById('template_<?php echo $product['id']; ?>').click()">
                                                        <span style="font-size: 11px; color: #65676b;">Click to upload</span>
                                                    </div>
                                                <?php endif; ?>
                                                <input type="file" id="template_<?php echo $product['id']; ?>" accept="image/*" style="display: none;"
                                                       onchange="uploadCustomPodFile(<?php echo $product['id']; ?>, 'template', this)">
                                            </div>
                                            
                                            <!-- Mockup Upload -->
                                            <div>
                                                <label style="display: block; font-weight: 600; font-size: 12px; margin-bottom: 5px; color: #333;">Mockup Image</label>
                                                <?php if (!empty($product['custom_mockup_url'])): ?>
                                                    <div style="position: relative; display: inline-block;">
                                                        <img src="/<?php echo ltrim(h($product['custom_mockup_url']), '/'); ?>" style="max-width: 100px; max-height: 80px; border-radius: 4px; border: 1px solid #ddd;">
                                                        <button onclick="removeCustomPodFile(<?php echo $product['id']; ?>, 'mockup')" 
                                                                style="position: absolute; top: -8px; right: -8px; background: #e41e3f; color: white; border: none; border-radius: 50%; width: 20px; height: 20px; cursor: pointer; font-size: 12px;">×</button>
                                                    </div>
                                                <?php else: ?>
                                                    <div style="border: 2px dashed #ccc; border-radius: 6px; padding: 15px; text-align: center; cursor: pointer; background: white;"
                                                         onclick="document.getElementById('mockup_<?php echo $product['id']; ?>').click()">
                                                        <span style="font-size: 11px; color: #65676b;">Click to upload</span>
                                                    </div>
                                                <?php endif; ?>
                                                <input type="file" id="mockup_<?php echo $product['id']; ?>" accept="image/*" style="display: none;"
                                                       onchange="uploadCustomPodFile(<?php echo $product['id']; ?>, 'mockup', this)">
                                            </div>
                                        </div>
                                        
                                        <!-- Template Dimensions (Collapsible) - Flat products only -->
                                        <div style="margin-bottom: 15px; <?php echo $isRound ? 'display: none;' : ''; ?>">
                                            <button type="button" onclick="toggleDimensions(<?php echo $product['id']; ?>)" 
                                                    style="background: #f0f2f5; border: 1px solid #ddd; border-radius: 6px; padding: 8px 12px; cursor: pointer; font-size: 12px; width: 100%; text-align: left;">
                                                <strong>📐 Template Dimensions</strong> <span style="float: right;">+</span>
                                            </button>
                                            <div id="dimensions_<?php echo $product['id']; ?>" style="display: none; background: #f9f9f9; padding: 12px; border-radius: 0 0 6px 6px; border: 1px solid #ddd; border-top: none;">
                                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 10px;">
                                                    <div>
                                                        <label style="font-size: 11px; color: #666;">Canvas Width</label>
                                                        <input type="number" id="canvas_width_<?php echo $product['id']; ?>" value="<?php echo $product['canvas_width'] ?? 500; ?>" 
                                                               style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                                    </div>
                                                    <div>
                                                        <label style="font-size: 11px; color: #666;">Canvas Height</label>
                                                        <input type="number" id="canvas_height_<?php echo $product['id']; ?>" value="<?php echo $product['canvas_height'] ?? 600; ?>" 
                                                               style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                                    </div>
                                                </div>
                                                <div style="display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 8px; margin-bottom: 10px;">
                                                    <div>
                                                        <label style="font-size: 11px; color: #666;">Target X</label>
                                                        <input type="number" id="target_x_<?php echo $product['id']; ?>" value="<?php echo $product['target_x'] ?? 50; ?>" 
                                                               style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                                    </div>
                                                    <div>
                                                        <label style="font-size: 11px; color: #666;">Target Y</label>
                                                        <input type="number" id="target_y_<?php echo $product['id']; ?>" value="<?php echo $product['target_y'] ?? 50; ?>" 
                                                               style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                                    </div>
                                                    <div>
                                                        <label style="font-size: 11px; color: #666;">Target W</label>
                                                        <input type="number" id="target_width_<?php echo $product['id']; ?>" value="<?php echo $product['target_width'] ?? 400; ?>" 
                                                               style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                                    </div>
                                                    <div>
                                                        <label style="font-size: 11px; color: #666;">Target H</label>
                                                        <input type="number" id="target_height_<?php echo $product['id']; ?>" value="<?php echo $product['target_height'] ?? 500; ?>" 
                                                               style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                                    </div>
                                                </div>
                                                <button type="button" onclick="saveDimensions(<?php echo $product['id']; ?>)" 
                                                        style="padding: 6px 12px; background: #1877f2; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 11px;">
                                                    Save Dimensions
                                                </button>
                                            </div>
                                        </div>
                                        
                                        <!-- Mockup Placement Settings (Collapsible) - Flat products only -->
                                        <div style="margin-bottom: 15px; <?php echo $isRound ? 'display: none;' : ''; ?>">
                                            <button type="button" onclick="toggleMockupPlacement(<?php echo $product['id']; ?>)" 
                                                    style="background: #e8f5e9; border: 1px solid #c8e6c9; border-radius: 6px; padding: 8px 12px; cursor: pointer; font-size: 12px; width: 100%; text-align: left;">
                                                <strong>🖼️ Mockup Placement</strong> <span style="float: right;">+</span>
                                            </button>
                                            <div id="mockup_placement_<?php echo $product['id']; ?>" style="display: none; background: #f9fff9; padding: 12px; border-radius: 0 0 6px 6px; border: 1px solid #c8e6c9; border-top: none;">
                                                <p style="font-size: 11px; color: #388e3c; margin: 0 0 10px 0;">
                                                    <strong>Where should the design appear on the mockup?</strong><br>
                                                    Enter values as percentages (0-100). E.g., X=25 means the design starts 25% from the left edge.
                                                </p>
                                                <div style="display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 8px; margin-bottom: 10px;">
                                                    <div>
                                                        <label style="font-size: 11px; color: #666;">X Position %</label>
                                                        <input type="number" id="mockup_x_<?php echo $product['id']; ?>" value="<?php echo $product['mockup_x'] ?? 25; ?>" 
                                                               min="0" max="100" step="1"
                                                               style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                                    </div>
                                                    <div>
                                                        <label style="font-size: 11px; color: #666;">Y Position %</label>
                                                        <input type="number" id="mockup_y_<?php echo $product['id']; ?>" value="<?php echo $product['mockup_y'] ?? 15; ?>" 
                                                               min="0" max="100" step="1"
                                                               style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                                    </div>
                                                    <div>
                                                        <label style="font-size: 11px; color: #666;">Width %</label>
                                                        <input type="number" id="mockup_width_<?php echo $product['id']; ?>" value="<?php echo $product['mockup_width'] ?? 50; ?>" 
                                                               min="1" max="100" step="1"
                                                               style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                                    </div>
                                                    <div>
                                                        <label style="font-size: 11px; color: #666;">Height %</label>
                                                        <input type="number" id="mockup_height_<?php echo $product['id']; ?>" value="<?php echo $product['mockup_height'] ?? 70; ?>" 
                                                               min="1" max="100" step="1"
                                                               style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                                    </div>
                                                </div>
                                                <p style="font-size: 10px; color: #666; margin: 8px 0;">
                                                    Tip: For a centered design, try X=25, Y=15, W=50, H=70
                                                </p>
                                                <button type="button" onclick="saveMockupPlacement(<?php echo $product['id']; ?>)" 
                                                        style="padding: 6px 12px; background: #4caf50; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 11px;">
                                                    Save Mockup Placement
                                                </button>
                                            </div>
                                        </div>
                                        
                                        <!-- Feed Text -->
                                        <div style="margin-bottom: 15px;">
                                            <label style="display: block; font-weight: 600; font-size: 12px; margin-bottom: 5px; color: #333;">Feed Post Text</label>
                                            <textarea id="feedtext_<?php echo $product['id']; ?>" 
                                                      placeholder="Text to include when posting to feed..."
                                                      style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px; resize: vertical; min-height: 60px;"
                                                      onchange="saveFeedText(<?php echo $product['id']; ?>)"><?php echo h($product['custom_feed_text'] ?? ''); ?></textarea>
                                        </div>
                                        
                                        <!-- 360 Preview Toggle - Round products only -->
                                        <div style="margin-bottom: 15px; padding: 12px; background: #f0f8ff; border-radius: 6px; border: 1px solid #b8daff; <?php echo !$isRound ? 'display: none;' : ''; ?>">
                                            <label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">
                                                <input type="checkbox" id="enable360_<?php echo $product['id']; ?>" 
                                                       <?php echo !empty($product['enable_360_preview']) ? 'checked' : ''; ?>
                                                       onchange="toggle360Preview(<?php echo $product['id']; ?>, this.checked)"
                                                       style="width: 18px; height: 18px; cursor: pointer;">
                                                <span style="font-weight: 600; font-size: 13px; color: #0066cc;">🔄 Enable 360° 3D Preview</span>
                                            </label>
                                            <p style="margin: 8px 0 0 28px; font-size: 11px; color: #666;">
                                                For cylindrical products. Customers can rotate the product to see the design from all angles.
                                            </p>
                                        </div>
                                        
                                        <!-- Product Measurements (for 3D products) - Round products only -->
                                        <div id="measurements_section_<?php echo $product['id']; ?>" style="margin-bottom: 15px; padding: 12px; background: #fff8e6; border-radius: 6px; border: 1px solid #ffc107; <?php echo (!$isRound || empty($product['enable_360_preview'])) ? 'display: none;' : ''; ?>">
                                            <strong style="font-size: 12px; color: #856404;">📏 Product Measurements (inches)</strong>
                                            <p style="font-size: 11px; color: #856404; margin: 5px 0 10px 0;">Enter exact dimensions for accurate 3D model</p>
                                            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;">
                                                <div>
                                                    <label style="font-size: 10px; color: #666; display: block;">Height</label>
                                                    <input type="number" step="0.01" id="meas_height_<?php echo $product['id']; ?>" 
                                                           value="<?php echo h($product['product_height'] ?? ''); ?>"
                                                           placeholder="e.g. 6.5"
                                                           style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                                </div>
                                                <div>
                                                    <label style="font-size: 10px; color: #666; display: block;">Top Diameter</label>
                                                    <input type="number" step="0.01" id="meas_top_<?php echo $product['id']; ?>" 
                                                           value="<?php echo h($product['top_diameter'] ?? ''); ?>"
                                                           placeholder="e.g. 3.5"
                                                           style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                                </div>
                                                <div>
                                                    <label style="font-size: 10px; color: #666; display: block;">Bottom Diameter</label>
                                                    <input type="number" step="0.01" id="meas_bottom_<?php echo $product['id']; ?>" 
                                                           value="<?php echo h($product['bottom_diameter'] ?? ''); ?>"
                                                           placeholder="e.g. 2.75"
                                                           style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                                </div>
                                            </div>
                                            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 10px;">
                                                <div>
                                                    <label style="font-size: 10px; color: #666; display: block;">Print Area Width</label>
                                                    <input type="number" step="0.01" id="meas_print_w_<?php echo $product['id']; ?>" 
                                                           value="<?php echo h($product['print_area_width'] ?? ''); ?>"
                                                           placeholder="e.g. 9.5"
                                                           style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                                </div>
                                                <div>
                                                    <label style="font-size: 10px; color: #666; display: block;">Print Area Height</label>
                                                    <input type="number" step="0.01" id="meas_print_h_<?php echo $product['id']; ?>" 
                                                           value="<?php echo h($product['print_area_height'] ?? ''); ?>"
                                                           placeholder="e.g. 4.0"
                                                           style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                                </div>
                                                <div>
                                                    <label style="font-size: 10px; color: #666; display: block;">Print Top Offset</label>
                                                    <input type="number" step="0.01" id="meas_offset_<?php echo $product['id']; ?>" 
                                                           value="<?php echo h($product['print_area_top_offset'] ?? ''); ?>"
                                                           placeholder="e.g. 1.0"
                                                           style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                                </div>
                                            </div>
                                            <button type="button" onclick="saveMeasurements(<?php echo $product['id']; ?>)" 
                                                    style="margin-top: 10px; padding: 8px 16px; background: #ffc107; color: #212529; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 600;">
                                                Save Measurements
                                            </button>
                                        </div>
                                        
                                        <!-- Variant Blank Mockups (Collapsible) - Round products only -->
                                        <div style="margin-bottom: 15px; <?php echo !$isRound ? 'display: none;' : ''; ?>">
                                            <button type="button" onclick="toggleVariantMockups(<?php echo $product['id']; ?>)" 
                                                    style="background: #e8f4e8; border: 1px solid #9ec79e; border-radius: 6px; padding: 8px 12px; cursor: pointer; font-size: 12px; width: 100%; text-align: left; color: #2d662d;">
                                                <strong>🖼️ Variant Blank Mockups</strong> <span style="float: right;">+</span>
                                            </button>
                                            <div id="variant_mockups_<?php echo $product['id']; ?>" style="display: none; background: #f9fdf9; padding: 12px; border-radius: 0 0 6px 6px; border: 1px solid #9ec79e; border-top: none;">
                                                <p style="font-size: 11px; color: #666; margin: 0 0 10px 0;">
                                                    Upload blank product images for each color variant. These will be used in the 360° 3D preview.
                                                </p>
                                                <div id="variant_list_<?php echo $product['id']; ?>" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 10px;">
                                                    <div style="text-align: center; color: #999; font-size: 11px; padding: 20px;">Loading variants...</div>
                                                </div>
                                            </div>
                                        </div>
                                        
                                        <!-- Action Buttons -->
                                        <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                                            <button onclick="saveForLater(<?php echo $product['id']; ?>)" 
                                                    style="padding: 10px 20px; background: #1877f2; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600;">
                                                Save for Later
                                            </button>
                                            <button onclick="postCustomPodToFeed(<?php echo $product['id']; ?>, '<?php echo h(addslashes($product['name'])); ?>')" 
                                                    style="padding: 10px 20px; background: #42b72a; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600;">
                                                Post to Feed
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                    
                    <script>
                    function uploadCustomPodFile(productId, type, input) {
                        if (!input.files || !input.files[0]) return;
                        
                        const formData = new FormData();
                        formData.append('action', 'upload_custom_pod_file');
                        formData.append('id', productId);
                        formData.append('type', type);
                        formData.append('file', input.files[0]);
                        
                        fetch('api/pod-admin.php', {
                            method: 'POST',
                            body: formData
                        })
                        .then(r => r.json())
                        .then(data => {
                            if (data.success) {
                                window.location.reload();
                            } else {
                                alert(data.error || 'Upload failed');
                            }
                        })
                        .catch(err => {
                            console.error('Upload error:', err);
                            alert('Upload failed. Please try again.');
                        });
                    }
                    
                    function removeCustomPodFile(productId, type) {
                        if (!confirm('Remove this ' + type + '?')) return;
                        
                        const formData = new FormData();
                        formData.append('action', 'remove_custom_pod_file');
                        formData.append('id', productId);
                        formData.append('type', type);
                        
                        fetch('api/pod-admin.php', {
                            method: 'POST',
                            body: formData
                        })
                        .then(r => r.json())
                        .then(data => {
                            if (data.success) {
                                window.location.reload();
                            } else {
                                alert(data.error || 'Failed to remove');
                            }
                        })
                        .catch(err => {
                            console.error('Remove error:', err);
                            alert('Failed to remove. Please try again.');
                        });
                    }
                    
                    function saveFeedText(productId) {
                        const text = document.getElementById('feedtext_' + productId).value;
                        
                        const formData = new FormData();
                        formData.append('action', 'save_feed_text');
                        formData.append('id', productId);
                        formData.append('text', text);
                        
                        fetch('api/pod-admin.php', {
                            method: 'POST',
                            body: formData
                        })
                        .then(r => r.json())
                        .then(data => {
                            if (!data.success) {
                                alert(data.error || 'Failed to save');
                            }
                        })
                        .catch(err => {
                            console.error('Save error:', err);
                        });
                    }
                    
                    function saveForLater(productId) {
                        // Save feed text
                        const text = document.getElementById('feedtext_' + productId).value;
                        
                        const formData = new FormData();
                        formData.append('action', 'save_feed_text');
                        formData.append('id', productId);
                        formData.append('text', text);
                        
                        // Also save dimensions if the section is visible
                        const dimSection = document.getElementById('dimensions_' + productId);
                        if (dimSection && dimSection.style.display !== 'none') {
                            formData.append('canvas_width', document.getElementById('canvas_width_' + productId).value);
                            formData.append('canvas_height', document.getElementById('canvas_height_' + productId).value);
                            formData.append('target_x', document.getElementById('target_x_' + productId).value);
                            formData.append('target_y', document.getElementById('target_y_' + productId).value);
                            formData.append('target_width', document.getElementById('target_width_' + productId).value);
                            formData.append('target_height', document.getElementById('target_height_' + productId).value);
                        }
                        
                        fetch('api/pod-admin.php', {
                            method: 'POST',
                            body: formData
                        })
                        .then(r => r.json())
                        .then(data => {
                            if (data.success) {
                                alert('Saved successfully! You can come back later to continue editing or post to feed.');
                            } else {
                                alert(data.error || 'Failed to save');
                            }
                        })
                        .catch(err => {
                            console.error('Save error:', err);
                            alert('Failed to save. Please try again.');
                        });
                    }
                    
                    function postCustomPodToFeed(productId, productName) {
                        if (!confirm('Post "' + productName + '" to the community feed?')) return;
                        
                        const formData = new FormData();
                        formData.append('action', 'post_custom_pod_to_feed');
                        formData.append('id', productId);
                        
                        fetch('api/pod-admin.php', {
                            method: 'POST',
                            body: formData
                        })
                        .then(r => r.json())
                        .then(data => {
                            if (data.success) {
                                alert('Posted to feed successfully!');
                            } else {
                                alert(data.error || 'Failed to post');
                            }
                        })
                        .catch(err => {
                            console.error('Post error:', err);
                            alert('Failed to post. Please try again.');
                        });
                    }
                    
                    function toggleDimensions(productId) {
                        const div = document.getElementById('dimensions_' + productId);
                        if (div.style.display === 'none') {
                            div.style.display = 'block';
                        } else {
                            div.style.display = 'none';
                        }
                    }
                    
                    function toggleMockupPlacement(productId) {
                        const div = document.getElementById('mockup_placement_' + productId);
                        if (div.style.display === 'none') {
                            div.style.display = 'block';
                        } else {
                            div.style.display = 'none';
                        }
                    }
                    
                    function saveMockupPlacement(productId) {
                        const formData = new FormData();
                        formData.append('action', 'save_mockup_placement');
                        formData.append('id', productId);
                        formData.append('mockup_x', document.getElementById('mockup_x_' + productId).value);
                        formData.append('mockup_y', document.getElementById('mockup_y_' + productId).value);
                        formData.append('mockup_width', document.getElementById('mockup_width_' + productId).value);
                        formData.append('mockup_height', document.getElementById('mockup_height_' + productId).value);
                        
                        fetch('api/pod-admin.php', {
                            method: 'POST',
                            body: formData
                        })
                        .then(r => r.json())
                        .then(data => {
                            if (data.success) {
                                alert('Mockup placement saved!');
                            } else {
                                alert(data.error || 'Failed to save');
                            }
                        })
                        .catch(err => alert('Error: ' + err.message));
                    }
                    
                    function toggle360Preview(productId, enabled) {
                        const formData = new FormData();
                        formData.append('action', 'toggle_360_preview');
                        formData.append('id', productId);
                        formData.append('enable_360_preview', enabled ? '1' : '0');
                        
                        // Show/hide measurements section
                        const measSection = document.getElementById('measurements_section_' + productId);
                        if (measSection) {
                            measSection.style.display = enabled ? 'block' : 'none';
                        }
                        
                        fetch('api/pod-admin.php', {
                            method: 'POST',
                            body: formData
                        })
                        .then(res => res.json())
                        .then(data => {
                            if (data.success) {
                                console.log('360 preview ' + (enabled ? 'enabled' : 'disabled'));
                            } else {
                                alert('Error: ' + (data.error || 'Failed to update'));
                            }
                        })
                        .catch(err => {
                            console.error(err);
                            alert('Error updating 360 preview setting');
                        });
                    }
                    
                    function saveMeasurements(productId) {
                        const formData = new FormData();
                        formData.append('action', 'save_measurements');
                        formData.append('id', productId);
                        formData.append('product_height', document.getElementById('meas_height_' + productId)?.value || '');
                        formData.append('top_diameter', document.getElementById('meas_top_' + productId)?.value || '');
                        formData.append('bottom_diameter', document.getElementById('meas_bottom_' + productId)?.value || '');
                        formData.append('print_area_width', document.getElementById('meas_print_w_' + productId)?.value || '');
                        formData.append('print_area_height', document.getElementById('meas_print_h_' + productId)?.value || '');
                        formData.append('print_area_top_offset', document.getElementById('meas_offset_' + productId)?.value || '');
                        
                        fetch('api/pod-admin.php', {
                            method: 'POST',
                            body: formData
                        })
                        .then(res => res.json())
                        .then(data => {
                            if (data.success) {
                                alert('Measurements saved!');
                            } else {
                                alert('Error: ' + (data.error || 'Failed to save measurements'));
                            }
                        })
                        .catch(err => {
                            console.error(err);
                            alert('Error saving measurements');
                        });
                    }
                    
                    function toggleVariantMockups(productId) {
                        const div = document.getElementById('variant_mockups_' + productId);
                        if (div.style.display === 'none') {
                            div.style.display = 'block';
                            loadVariantMockups(productId);
                        } else {
                            div.style.display = 'none';
                        }
                    }
                    
                    function loadVariantMockups(productId) {
                        const container = document.getElementById('variant_list_' + productId);
                        
                        fetch('api/pod-admin.php?action=get_variants&product_id=' + productId)
                        .then(res => res.json())
                        .then(data => {
                            if (data.success && data.variants) {
                                container.innerHTML = data.variants.map(v => `
                                    <div style="text-align: center; background: white; padding: 10px; border-radius: 6px; border: 1px solid #ddd;">
                                        <div style="font-size: 11px; font-weight: 600; margin-bottom: 8px; color: #333;">
                                            ${v.color ? v.color : ''}${v.size && v.color ? ' - ' : ''}${v.size ? v.size : ''}${!v.color && !v.size ? 'Variant' : ''}
                                        </div>
                                        ${v.blank_mockup_url ? `
                                            <div style="position: relative; display: inline-block;">
                                                <img src="${v.blank_mockup_url}" style="width: 80px; height: 80px; object-fit: contain; border-radius: 4px; border: 1px solid #ddd;">
                                                <button onclick="removeVariantBlankMockup(${v.id}, ${productId})" 
                                                        style="position: absolute; top: -6px; right: -6px; background: #e41e3f; color: white; border: none; border-radius: 50%; width: 18px; height: 18px; cursor: pointer; font-size: 10px;">×</button>
                                            </div>
                                        ` : `
                                            <div style="width: 80px; height: 80px; border: 2px dashed #ccc; border-radius: 6px; display: flex; align-items: center; justify-content: center; cursor: pointer; margin: 0 auto;"
                                                 onclick="document.getElementById('blank_mockup_${v.id}').click()">
                                                <span style="font-size: 24px; color: #ccc;">+</span>
                                            </div>
                                        `}
                                        <input type="file" id="blank_mockup_${v.id}" accept="image/*" style="display: none;"
                                               onchange="uploadVariantBlankMockup(${v.id}, ${productId}, this)">
                                    </div>
                                `).join('');
                            } else {
                                container.innerHTML = '<div style="color: #999; font-size: 11px; padding: 10px;">No variants found</div>';
                            }
                        })
                        .catch(err => {
                            console.error(err);
                            container.innerHTML = '<div style="color: #e41e3f; font-size: 11px; padding: 10px;">Error loading variants</div>';
                        });
                    }
                    
                    function uploadVariantBlankMockup(variantId, productId, input) {
                        if (!input.files || !input.files[0]) return;
                        
                        const formData = new FormData();
                        formData.append('action', 'upload_variant_blank_mockup');
                        formData.append('variant_id', variantId);
                        formData.append('file', input.files[0]);
                        
                        fetch('api/pod-admin.php', {
                            method: 'POST',
                            body: formData
                        })
                        .then(res => res.json())
                        .then(data => {
                            if (data.success) {
                                loadVariantMockups(productId);
                            } else {
                                alert('Error: ' + (data.error || 'Upload failed'));
                            }
                        })
                        .catch(err => {
                            console.error(err);
                            alert('Upload error');
                        });
                        
                        input.value = '';
                    }
                    
                    function removeVariantBlankMockup(variantId, productId) {
                        if (!confirm('Remove this blank mockup?')) return;
                        
                        const formData = new FormData();
                        formData.append('action', 'remove_variant_blank_mockup');
                        formData.append('variant_id', variantId);
                        
                        fetch('api/pod-admin.php', {
                            method: 'POST',
                            body: formData
                        })
                        .then(res => res.json())
                        .then(data => {
                            if (data.success) {
                                loadVariantMockups(productId);
                            } else {
                                alert('Error: ' + (data.error || 'Remove failed'));
                            }
                        })
                        .catch(err => {
                            console.error(err);
                            alert('Remove error');
                        });
                    }
                    
                    function saveDimensions(productId) {
                        const formData = new FormData();
                        formData.append('action', 'save_dimensions');
                        formData.append('id', productId);
                        formData.append('canvas_width', document.getElementById('canvas_width_' + productId).value);
                        formData.append('canvas_height', document.getElementById('canvas_height_' + productId).value);
                        formData.append('target_x', document.getElementById('target_x_' + productId).value);
                        formData.append('target_y', document.getElementById('target_y_' + productId).value);
                        formData.append('target_width', document.getElementById('target_width_' + productId).value);
                        formData.append('target_height', document.getElementById('target_height_' + productId).value);
                        
                        fetch('api/pod-admin.php', {
                            method: 'POST',
                            body: formData
                        })
                        .then(r => r.json())
                        .then(data => {
                            if (data.success) {
                                alert('Dimensions saved!');
                            } else {
                                alert(data.error || 'Failed to save');
                            }
                        })
                        .catch(err => {
                            console.error('Save error:', err);
                            alert('Failed to save dimensions.');
                        });
                    }
                    </script>
                <?php endif; ?>

            <?php elseif ($activeTab === 'orders'): ?>
                <?php
                $ordersStmt = $pdo->query("
                    SELECT 
                        co.order_id,
                        co.printify_order_id,
                        co.status,
                        co.printify_status,
                        co.shipment_data,
                        co.shipping_name,
                        co.shipping_city,
                        co.shipping_state,
                        co.created_at,
                        COALESCE(CONCAT(u.first_name, ' ', u.last_name), 'Guest') as username,
                        u.email as user_email,
                        pp.name as product_name
                    FROM custom_orders co
                    LEFT JOIN users u ON co.user_id = u.id
                    LEFT JOIN pod_products pp ON co.product_id = pp.id
                    WHERE co.printify_order_id IS NOT NULL
                    ORDER BY co.created_at DESC
                    LIMIT 100
                ");
                $podOrders = $ordersStmt->fetchAll();
                ?>
                
                <h2>POD Orders</h2>
                <p style="color: #65676b; margin-bottom: 20px;">View and track orders sent to Printify for fulfillment.</p>
                
                <?php if (isset($_GET['test_mode_updated'])): ?>
                    <div class="alert alert-success">Test mode setting updated!</div>
                <?php endif; ?>
                
                <?php
                $testModeStmt = $pdo->prepare("SELECT setting_value FROM site_settings WHERE setting_key = 'checkout_test_mode'");
                $testModeStmt->execute();
                $testModeResult = $testModeStmt->fetch();
                $testModeEnabled = ($testModeResult && $testModeResult['setting_value'] === 'true');
                ?>
                
                <div style="background: <?php echo $testModeEnabled ? '#d4edda' : '#f8f9fa'; ?>; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 2px solid <?php echo $testModeEnabled ? '#28a745' : '#e4e6e9'; ?>;">
                    <form method="post" style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 15px;">
                        <input type="hidden" name="action" value="toggle_test_mode">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div>
                            <h4 style="margin: 0 0 5px 0; color: <?php echo $testModeEnabled ? '#155724' : '#333'; ?>;">
                                Checkout Test Mode <?php echo $testModeEnabled ? '(ENABLED)' : '(Disabled)'; ?>
                            </h4>
                            <p style="margin: 0; font-size: 13px; color: #65676b;">
                                <?php if ($testModeEnabled): ?>
                                    Using Square Sandbox - No real charges will be made. Test card: 4111 1111 1111 1111
                                <?php else: ?>
                                    Production mode - Real payments will be processed
                                <?php endif; ?>
                            </p>
                        </div>
                        <label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">
                            <input type="checkbox" name="test_mode_enabled" <?php echo $testModeEnabled ? 'checked' : ''; ?> 
                                   onchange="this.form.submit()" style="width: 20px; height: 20px;">
                            <span style="font-weight: 600;">Enable Test Mode</span>
                        </label>
                    </form>
                </div>
                
                <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #ffc107;">
                    <h4 style="margin: 0 0 10px 0; color: #856404;">Printify Webhook Setup</h4>
                    <p style="margin: 0 0 10px 0; color: #856404; font-size: 14px;">
                        For automatic order status updates, add this webhook URL in your Printify account:
                    </p>
                    <code style="background: #fff; padding: 8px 12px; border-radius: 4px; display: block; font-size: 13px; color: #333;">
                        <?php echo (isset($_SERVER['HTTPS']) ? 'https://' : 'http://') . $_SERVER['HTTP_HOST']; ?>/api/printify-webhook.php
                    </code>
                    <p style="margin: 10px 0 0 0; font-size: 12px; color: #856404;">
                        Subscribe to: order:created, order:sent-to-production, order:shipped, order:fulfilled
                    </p>
                </div>
                
                <div style="margin-bottom: 20px;">
                    <button onclick="syncOrderStatuses()" class="btn" style="background: #1877f2; color: white; padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer;">
                        Sync All Order Statuses
                    </button>
                    <span id="syncStatus" style="margin-left: 10px; color: #65676b;"></span>
                </div>
                
                <?php if (count($podOrders) === 0): ?>
                    <div style="text-align: center; padding: 40px; background: #f0f2f5; border-radius: 8px;">
                        <p style="color: #65676b;">No POD orders found. Orders will appear here once customers purchase customized products.</p>
                    </div>
                <?php else: ?>
                    <div style="overflow-x: auto;">
                        <table style="width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden;">
                            <thead>
                                <tr style="background: #f0f2f5;">
                                    <th style="padding: 12px; text-align: left; border-bottom: 1px solid #e4e6e9;">Order ID</th>
                                    <th style="padding: 12px; text-align: left; border-bottom: 1px solid #e4e6e9;">Product</th>
                                    <th style="padding: 12px; text-align: left; border-bottom: 1px solid #e4e6e9;">Customer</th>
                                    <th style="padding: 12px; text-align: left; border-bottom: 1px solid #e4e6e9;">Ship To</th>
                                    <th style="padding: 12px; text-align: left; border-bottom: 1px solid #e4e6e9;">Status</th>
                                    <th style="padding: 12px; text-align: left; border-bottom: 1px solid #e4e6e9;">Printify Status</th>
                                    <th style="padding: 12px; text-align: left; border-bottom: 1px solid #e4e6e9;">Created</th>
                                    <th style="padding: 12px; text-align: left; border-bottom: 1px solid #e4e6e9;">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($podOrders as $order): ?>
                                    <?php
                                    $printifyStatus = $order['printify_status'] ?? 'pending';
                                    $statusColors = [
                                        'pending' => '#ffc107',
                                        'on-hold' => '#ffc107',
                                        'in-production' => '#17a2b8',
                                        'shipped' => '#28a745',
                                        'fulfilled' => '#28a745',
                                        'canceled' => '#dc3545',
                                        'refunded' => '#6c757d'
                                    ];
                                    $statusColor = $statusColors[$printifyStatus] ?? '#6c757d';
                                    $shipments = $order['shipment_data'] ? json_decode($order['shipment_data'], true) : [];
                                    ?>
                                    <tr>
                                        <td style="padding: 12px; border-bottom: 1px solid #e4e6e9;">
                                            <span style="font-family: monospace; font-size: 12px;"><?php echo h(substr($order['order_id'], 0, 8)); ?>...</span>
                                            <?php if ($order['printify_order_id']): ?>
                                                <br><small style="color: #65676b;">Printify: <?php echo h(substr($order['printify_order_id'], 0, 10)); ?>...</small>
                                            <?php endif; ?>
                                        </td>
                                        <td style="padding: 12px; border-bottom: 1px solid #e4e6e9;">
                                            <?php echo h($order['product_name'] ?? 'Unknown Product'); ?>
                                        </td>
                                        <td style="padding: 12px; border-bottom: 1px solid #e4e6e9;">
                                            <?php echo h($order['username'] ?? 'Guest'); ?>
                                            <?php if ($order['user_email']): ?>
                                                <br><small style="color: #65676b;"><?php echo h($order['user_email']); ?></small>
                                            <?php endif; ?>
                                        </td>
                                        <td style="padding: 12px; border-bottom: 1px solid #e4e6e9;">
                                            <?php echo h($order['shipping_name'] ?? ''); ?>
                                            <?php if ($order['shipping_city']): ?>
                                                <br><small style="color: #65676b;"><?php echo h($order['shipping_city'] . ', ' . $order['shipping_state']); ?></small>
                                            <?php endif; ?>
                                        </td>
                                        <td style="padding: 12px; border-bottom: 1px solid #e4e6e9;">
                                            <span style="background: <?php echo $order['status'] === 'submitted' ? '#28a745' : '#ffc107'; ?>; color: white; padding: 3px 8px; border-radius: 4px; font-size: 12px;">
                                                <?php echo h(ucfirst($order['status'] ?? 'pending')); ?>
                                            </span>
                                        </td>
                                        <td style="padding: 12px; border-bottom: 1px solid #e4e6e9;">
                                            <span style="background: <?php echo $statusColor; ?>; color: white; padding: 3px 8px; border-radius: 4px; font-size: 12px;">
                                                <?php echo h(ucfirst(str_replace('-', ' ', $printifyStatus))); ?>
                                            </span>
                                            <?php if (!empty($shipments)): ?>
                                                <br><small style="color: #28a745; margin-top: 4px; display: block;">
                                                    <?php 
                                                    foreach ($shipments as $shipment) {
                                                        if (isset($shipment['tracking_number'])) {
                                                            echo 'Tracking: ' . h($shipment['tracking_number']);
                                                            break;
                                                        }
                                                    }
                                                    ?>
                                                </small>
                                            <?php endif; ?>
                                        </td>
                                        <td style="padding: 12px; border-bottom: 1px solid #e4e6e9;">
                                            <small><?php echo date('M j, Y g:ia', strtotime($order['created_at'])); ?></small>
                                        </td>
                                        <td style="padding: 12px; border-bottom: 1px solid #e4e6e9;">
                                            <button onclick="refreshOrder('<?php echo h($order['printify_order_id']); ?>')" 
                                                    style="background: #e4e6e9; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; font-size: 12px;">
                                                Refresh
                                            </button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
                
                <script>
                function syncOrderStatuses() {
                    document.getElementById('syncStatus').textContent = 'Syncing...';
                    fetch('api/printify-orders.php?action=sync')
                        .then(r => r.json())
                        .then(data => {
                            if (data.success) {
                                document.getElementById('syncStatus').textContent = 
                                    `Synced ${data.updated}/${data.total} orders`;
                                setTimeout(() => location.reload(), 1500);
                            } else {
                                document.getElementById('syncStatus').textContent = 
                                    'Error: ' + (data.error || 'Sync failed');
                            }
                        })
                        .catch(err => {
                            document.getElementById('syncStatus').textContent = 'Error: ' + err.message;
                        });
                }
                
                function refreshOrder(printifyOrderId) {
                    fetch('api/printify-orders.php?action=refresh&printify_order_id=' + encodeURIComponent(printifyOrderId))
                        .then(r => r.json())
                        .then(data => {
                            if (data.success) {
                                location.reload();
                            } else {
                                alert('Error: ' + (data.error || 'Failed to refresh'));
                            }
                        })
                        .catch(err => alert('Error: ' + err.message));
                }
                </script>

            <?php elseif ($activeTab === 'catalog'): ?>
                <h2>Create New Product</h2>
                <p style="color: #65676b; margin-bottom: 20px;">Choose a product type, select your options, and upload your design. It only takes a few minutes!</p>
                
                <!-- Quick Start Templates -->
                <div id="quickTemplates" style="background: linear-gradient(135deg, #e7f3ff 0%, #f8f9fa 100%); border-radius: 12px; padding: 20px; margin-bottom: 25px;">
                    <h4 style="margin: 0 0 15px; color: #1877f2; display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 20px;"></span> Quick Start - Popular Products
                    </h4>
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 12px;">
                        <button onclick="quickSelectBlueprint(5, 'Unisex Heavy Cotton Tee')" class="quick-template-btn" style="background: white; border: 2px solid #1877f2; border-radius: 10px; padding: 15px; cursor: pointer; text-align: center; transition: all 0.2s;">
                            <div style="font-size: 28px; margin-bottom: 8px;">T-Shirt</div>
                            <div style="font-weight: 600; color: #1877f2;">Unisex Tee</div>
                            <div style="font-size: 11px; color: #65676b; margin-top: 4px;">Best Seller</div>
                        </button>
                        <button onclick="quickSelectBlueprint(77, 'Unisex Heavy Blend Hoodie')" class="quick-template-btn" style="background: white; border: 2px solid #e4e6e9; border-radius: 10px; padding: 15px; cursor: pointer; text-align: center; transition: all 0.2s;">
                            <div style="font-size: 28px; margin-bottom: 8px;">Hoodie</div>
                            <div style="font-weight: 600; color: #333;">Hoodie</div>
                            <div style="font-size: 11px; color: #65676b; margin-top: 4px;">Cozy & Warm</div>
                        </button>
                        <button onclick="quickSelectBlueprint(378, 'White Mug')" class="quick-template-btn" style="background: white; border: 2px solid #e4e6e9; border-radius: 10px; padding: 15px; cursor: pointer; text-align: center; transition: all 0.2s;">
                            <div style="font-size: 28px; margin-bottom: 8px;">Mug</div>
                            <div style="font-weight: 600; color: #333;">Ceramic Mug</div>
                            <div style="font-size: 11px; color: #65676b; margin-top: 4px;">11oz Classic</div>
                        </button>
                        <button onclick="quickSelectBlueprint(523, 'Sticker')" class="quick-template-btn" style="background: white; border: 2px solid #e4e6e9; border-radius: 10px; padding: 15px; cursor: pointer; text-align: center; transition: all 0.2s;">
                            <div style="font-size: 28px; margin-bottom: 8px;">Sticker</div>
                            <div style="font-weight: 600; color: #333;">Die Cut Sticker</div>
                            <div style="font-size: 11px; color: #65676b; margin-top: 4px;">Vinyl</div>
                        </button>
                        <button onclick="quickSelectBlueprint(1050, 'Baseball Cap')" class="quick-template-btn" style="background: white; border: 2px solid #e4e6e9; border-radius: 10px; padding: 15px; cursor: pointer; text-align: center; transition: all 0.2s;">
                            <div style="font-size: 28px; margin-bottom: 8px;">Hat</div>
                            <div style="font-weight: 600; color: #333;">Baseball Cap</div>
                            <div style="font-size: 11px; color: #65676b; margin-top: 4px;">Adjustable</div>
                        </button>
                    </div>
                </div>
                <style>
                .quick-template-btn:hover { border-color: #1877f2 !important; transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
                </style>
                
                <div id="catalogContainer">
                    <div style="margin-bottom: 20px;">
                        <label style="display: block; margin-bottom: 8px; font-weight: 600; color: #333;">Or browse all products:</label>
                        <input type="text" id="blueprintSearch" placeholder="Search products by name..." 
                               style="width: 100%; max-width: 400px; padding: 12px 15px; border: 1px solid #e4e6e9; border-radius: 8px; font-size: 15px;"
                               oninput="filterBlueprints()">
                    </div>
                    
                    <div id="loadingBlueprints" style="text-align: center; padding: 40px;">
                        <p>Loading product catalog...</p>
                    </div>
                    
                    <div id="blueprintsGrid" style="display: none; display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px;"></div>
                </div>
                
                <div id="productCreator" style="display: none; background: #f0f2f5; padding: 20px; border-radius: 8px; margin-top: 20px;">
                    <button onclick="backToCatalog()" style="background: #e4e6e9; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer; margin-bottom: 15px;">
                        &larr; Back to Catalog
                    </button>
                    
                    <h3 id="selectedBlueprintName" style="margin-top: 0; margin-bottom: 10px;"></h3>
                    <p id="blueprintBrandModel" style="margin: 0 0 15px; color: #65676b; font-size: 14px;"></p>
                    
                    <div id="blueprintImages" style="display: none; margin-bottom: 20px;">
                        <h5 style="margin: 0 0 10px;">Product Images</h5>
                        <div id="blueprintImagesGrid" style="display: flex; gap: 10px; overflow-x: auto; padding-bottom: 10px;"></div>
                    </div>
                    
                    <div id="step1" style="margin-bottom: 20px;">
                        <h4 style="color: #1877f2; display: flex; align-items: center; gap: 10px;">
                            <span style="background: #1877f2; color: white; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 14px;">1</span>
                            Choose a Manufacturer
                        </h4>
                        <p style="color: #65676b; margin: 0 0 15px; font-size: 14px;">Select who will print and ship your products. We recommend the first option for fastest shipping.</p>
                        <div id="providersLoading">Loading manufacturers...</div>
                        <div id="providersList" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 10px;"></div>
                    </div>
                    
                    <div id="step2" style="display: none; margin-bottom: 20px;">
                        <h4 style="color: #1877f2; display: flex; align-items: center; gap: 10px;">
                            <span style="background: #1877f2; color: white; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 14px;">2</span>
                            Select Colors & Sizes
                        </h4>
                        <p style="color: #65676b; margin: 0 0 15px; font-size: 14px;">Choose which color and size options to offer. All options are selected by default - uncheck any you don't want to sell.</p>
                        <div id="variantsSummary" style="display: none; background: #d4edda; border: 1px solid #28a745; border-radius: 6px; padding: 12px; margin-bottom: 10px;">
                            <div style="display: flex; gap: 20px; flex-wrap: wrap; align-items: center;">
                                <span style="color: #155724; font-weight: 600;"><span id="selectedCount2">0</span> options selected</span>
                                <div><strong>Colors:</strong> <span id="colorCount">0</span></div>
                                <div><strong>Sizes:</strong> <span id="sizeCount">0</span></div>
                            </div>
                        </div>
                        <div id="colorSwatches" style="display: none; margin-bottom: 15px;">
                            <h5 style="margin: 0 0 10px; font-size: 14px;">Available Colors</h5>
                            <div id="colorSwatchesGrid" style="display: flex; flex-wrap: wrap; gap: 8px;"></div>
                        </div>
                        <div id="sizeChart" style="display: none; margin-bottom: 15px; background: #f8f9fa; border-radius: 8px; padding: 15px;">
                            <h5 style="margin: 0 0 10px; display: flex; align-items: center; gap: 10px; font-size: 14px;">
                                Available Sizes
                                <a id="printifySizeGuideLink" href="#" target="_blank" style="font-size: 12px; font-weight: normal; color: #1877f2; text-decoration: none;">(View size guide)</a>
                            </h5>
                            <div id="sizeChartGrid" style="display: flex; flex-wrap: wrap; gap: 8px;"></div>
                        </div>
                        <div id="variantsLoading">Loading options...</div>
                        <details id="variantsDetails" style="margin-bottom: 10px;">
                            <summary style="cursor: pointer; padding: 10px; background: #f0f2f5; border-radius: 6px; font-weight: 600;">View/Edit Individual Options</summary>
                            <div id="variantsList" style="max-height: 300px; overflow-y: auto; border: 1px solid #e4e6e9; border-radius: 6px; padding: 10px; background: white; margin-top: 10px;"></div>
                        </details>
                        <div style="margin-top: 10px; display: flex; gap: 10px; align-items: center;">
                            <button onclick="selectAllVariants()" style="background: #1877f2; color: white; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer;">Select All</button>
                            <button onclick="deselectAllVariants()" style="background: #e4e6e9; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer;">Deselect All</button>
                            <span id="selectedCount" style="color: #65676b;">0 selected</span>
                        </div>
                    </div>
                    
                    <div id="step3" style="display: none; margin-bottom: 20px;">
                        <h4 style="color: #1877f2; display: flex; align-items: center; gap: 10px;">
                            <span style="background: #1877f2; color: white; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 14px;">3</span>
                            Add Your Design
                        </h4>
                        <p style="color: #65676b; margin: 0 0 15px; font-size: 14px;">Upload your artwork and customize the product details.</p>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                            <div>
                                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Product Name</label>
                                <input type="text" id="productTitle" placeholder="e.g., My Awesome T-Shirt" 
                                       style="width: 100%; padding: 10px; border: 1px solid #e4e6e9; border-radius: 6px; margin-bottom: 15px;">
                                
                                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Description <span style="font-weight: normal; color: #65676b;">(optional)</span></label>
                                <textarea id="productDescription" placeholder="Describe your product..." rows="3"
                                          style="width: 100%; padding: 10px; border: 1px solid #e4e6e9; border-radius: 6px; margin-bottom: 15px;"></textarea>
                                
                                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Design Image <span style="color: #dc3545;">*</span></label>
                                <div id="uploadArea" style="border: 2px dashed #1877f2; border-radius: 8px; padding: 20px; text-align: center; background: #f8f9fa; margin-bottom: 10px; cursor: pointer;" onclick="document.getElementById('designFile').click()">
                                    <input type="file" id="designFile" accept="image/*" style="display: none;" onchange="handleDesignUpload(this);">
                                    <div id="uploadPrompt">
                                        <div style="font-size: 40px; margin-bottom: 10px;">+</div>
                                        <div style="font-weight: 600; color: #1877f2;">Click to upload your design</div>
                                        <div style="font-size: 12px; color: #65676b; margin-top: 5px;">PNG with transparent background recommended</div>
                                    </div>
                                </div>
                                
                                <label style="display: flex; align-items: center; gap: 8px; cursor: pointer; margin-top: 10px;">
                                    <input type="checkbox" id="autoPublish" checked style="width: 18px; height: 18px;"> 
                                    <span>Make product available for sale immediately</span>
                                </label>
                            </div>
                            <div>
                                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Artwork</label>
                                <div id="designPreview" style="width: 100%; height: 300px; border: 2px dashed #e4e6e9; border-radius: 6px; display: flex; align-items: center; justify-content: center; background: #fafafa;">
                                    <span style="color: #65676b;">No design uploaded</span>
                                </div>
                            </div>
                        </div>
                        
                        <div style="margin-top: 20px; text-align: center;">
                            <button onclick="createProduct()" id="createBtn" disabled style="background: #ccc; color: white; border: none; padding: 15px 40px; border-radius: 8px; cursor: not-allowed; font-size: 18px; font-weight: 600;">
                                Create Product
                            </button>
                            <p id="createBtnHint" style="font-size: 12px; color: #65676b; margin: 8px 0 0;">Upload your design image to enable this button</p>
                            <div id="createStatus" style="margin-top: 10px; color: #65676b; font-size: 14px;"></div>
                        </div>
                    </div>
                    
                    <div id="creationSuccess" style="display: none; background: #d4edda; border: 1px solid #28a745; border-radius: 8px; padding: 20px; margin-top: 20px;">
                        <h4 style="margin: 0 0 15px; color: #155724;">Product Created Successfully!</h4>
                        <p style="margin: 0 0 10px;"><strong>Product ID:</strong> <span id="createdProductId"></span></p>
                        <div id="productMockups" style="margin-top: 15px;">
                            <h5 style="margin: 0 0 10px;">Product Mockups</h5>
                            <div id="mockupsGrid" style="display: flex; gap: 15px; flex-wrap: wrap;"></div>
                            <p id="mockupsLoading" style="color: #65676b;">Loading mockups...</p>
                        </div>
                        <div style="margin-top: 20px;">
                            <button onclick="backToCatalog()" style="background: #1877f2; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer;">
                                Create Another Product
                            </button>
                        </div>
                    </div>
                </div>
                
                <script>
                let allBlueprints = [];
                let selectedBlueprint = null;
                let selectedProvider = null;
                let allVariants = [];
                
                document.addEventListener('DOMContentLoaded', loadBlueprints);
                
                // Quick template selection - skips browsing and goes straight to the product
                function quickSelectBlueprint(blueprintId, title) {
                    // Hide quick templates and catalog
                    document.getElementById('quickTemplates').style.display = 'none';
                    selectBlueprint(blueprintId, title);
                }
                
                function loadBlueprints() {
                    fetch('api/publish-to-printify.php?action=blueprints')
                        .then(r => r.json())
                        .then(data => {
                            document.getElementById('loadingBlueprints').style.display = 'none';
                            document.getElementById('blueprintsGrid').style.display = 'grid';
                            
                            if (data.error) {
                                document.getElementById('blueprintsGrid').innerHTML = '<p style="color: #dc3545;">Error: ' + data.error + '</p>';
                                return;
                            }
                            
                            allBlueprints = data.blueprints || data;
                            renderBlueprints(allBlueprints);
                        })
                        .catch(err => {
                            document.getElementById('loadingBlueprints').innerHTML = '<p style="color: #dc3545;">Error loading catalog: ' + err.message + '</p>';
                        });
                }
                
                function getBlueprintImage(bp) {
                    if (!bp.images || bp.images.length === 0) return '';
                    const img = bp.images[0];
                    return typeof img === 'string' ? img : (img.src || img.url || '');
                }
                
                function renderBlueprints(blueprints) {
                    const grid = document.getElementById('blueprintsGrid');
                    grid.innerHTML = blueprints.slice(0, 100).map(bp => `
                        <div onclick="selectBlueprintById(${bp.id})" 
                             style="background: white; border: 1px solid #e4e6e9; border-radius: 8px; padding: 10px; cursor: pointer; transition: box-shadow 0.2s;"
                             onmouseover="this.style.boxShadow='0 2px 8px rgba(0,0,0,0.1)'" 
                             onmouseout="this.style.boxShadow='none'">
                            <img src="${getBlueprintImage(bp)}" alt="${escapeHtml(bp.title)}" 
                                 style="width: 100%; height: 150px; object-fit: contain; background: #f8f9fa; border-radius: 4px;"
                                 onerror="this.style.display='none'">
                            <h4 style="margin: 10px 0 5px; font-size: 14px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(bp.title)}</h4>
                            <p style="margin: 0; font-size: 12px; color: #65676b;">ID: ${bp.id}</p>
                        </div>
                    `).join('');
                    
                    if (blueprints.length > 100) {
                        grid.innerHTML += '<p style="grid-column: 1/-1; text-align: center; color: #65676b;">Showing first 100 of ' + blueprints.length + ' products. Use search to find more.</p>';
                    }
                }
                
                function filterBlueprints() {
                    const search = document.getElementById('blueprintSearch').value.toLowerCase();
                    const filtered = allBlueprints.filter(bp => bp.title.toLowerCase().includes(search));
                    renderBlueprints(filtered);
                }
                
                let selectedBlueprintTitle = '';
                
                function selectBlueprintById(id) {
                    const bp = allBlueprints.find(b => b.id === id);
                    const title = bp ? bp.title : 'Product';
                    selectBlueprint(id, title);
                }
                
                function selectBlueprint(id, title) {
                    selectedBlueprint = id;
                    selectedBlueprintTitle = title;
                    document.getElementById('catalogContainer').style.display = 'none';
                    document.getElementById('productCreator').style.display = 'block';
                    document.getElementById('selectedBlueprintName').textContent = title;
                    document.getElementById('productTitle').value = title;
                    document.getElementById('step2').style.display = 'none';
                    document.getElementById('step3').style.display = 'none';
                    
                    // Fetch blueprint details for description and images
                    fetch('api/publish-to-printify.php?action=blueprint_details&blueprint_id=' + id)
                        .then(r => r.json())
                        .then(data => {
                            if (data.description) {
                                document.getElementById('productDescription').value = data.description;
                            }
                            // Show brand and model
                            const brandModel = [data.brand, data.model].filter(Boolean).join(' - ');
                            document.getElementById('blueprintBrandModel').textContent = brandModel;
                            
                            // Show product images
                            if (data.images && data.images.length > 0) {
                                document.getElementById('blueprintImages').style.display = 'block';
                                document.getElementById('blueprintImagesGrid').innerHTML = data.images.map(img => {
                                    const imgSrc = typeof img === 'string' ? img : (img.src || img.url || '');
                                    return `
                                    <img src="${imgSrc}" alt="Product image" 
                                         style="height: 120px; width: auto; border-radius: 6px; border: 1px solid #e4e6e9; cursor: pointer; flex-shrink: 0;"
                                         onclick="window.open('${imgSrc}', '_blank')"
                                         onerror="this.style.display='none'">
                                `}).join('');
                            } else {
                                document.getElementById('blueprintImages').style.display = 'none';
                            }
                        })
                        .catch(() => {});
                    
                    loadProviders(id);
                }
                
                function loadProviders(blueprintId) {
                    document.getElementById('providersLoading').style.display = 'block';
                    document.getElementById('providersList').innerHTML = '';
                    
                    fetch('api/publish-to-printify.php?action=providers&blueprint_id=' + blueprintId)
                        .then(r => r.json())
                        .then(data => {
                            document.getElementById('providersLoading').style.display = 'none';
                            
                            if (data.error) {
                                document.getElementById('providersList').innerHTML = '<p style="color: #dc3545;">Error: ' + data.error + '</p>';
                                return;
                            }
                            
                            const providers = data.providers || data;
                            document.getElementById('providersList').innerHTML = providers.map(p => `
                                <div onclick="selectProvider(${p.id}, '${escapeHtml(p.title)}')" 
                                     style="background: white; border: 1px solid #e4e6e9; border-radius: 6px; padding: 15px; cursor: pointer;"
                                     onmouseover="this.style.borderColor='#1877f2'" 
                                     onmouseout="this.style.borderColor='#e4e6e9'">
                                    <strong>${escapeHtml(p.title)}</strong>
                                    <p style="margin: 5px 0 0; font-size: 12px; color: #65676b;">Location: ${p.location?.country || 'Unknown'}</p>
                                </div>
                            `).join('');
                        })
                        .catch(err => {
                            document.getElementById('providersList').innerHTML = '<p style="color: #dc3545;">Error: ' + err.message + '</p>';
                        });
                }
                
                function selectProvider(id, title) {
                    selectedProvider = id;
                    document.getElementById('step2').style.display = 'block';
                    loadVariants(selectedBlueprint, id);
                }
                
                function loadVariants(blueprintId, providerId) {
                    document.getElementById('variantsLoading').style.display = 'block';
                    document.getElementById('variantsList').innerHTML = '';
                    
                    fetch('api/publish-to-printify.php?action=variants&blueprint_id=' + blueprintId + '&provider_id=' + providerId)
                        .then(r => r.json())
                        .then(data => {
                            document.getElementById('variantsLoading').style.display = 'none';
                            
                            if (data.error) {
                                document.getElementById('variantsList').innerHTML = '<p style="color: #dc3545;">Error: ' + data.error + '</p>';
                                return;
                            }
                            
                            allVariants = data.variants || data;
                            
                            // Extract colors and sizes from variant titles/options
                            const colors = new Set();
                            const sizes = new Set();
                            allVariants.forEach(v => {
                                // Try to parse from options object first
                                if (v.options) {
                                    if (v.options.color) colors.add(v.options.color);
                                    if (v.options.size) sizes.add(v.options.size);
                                }
                                // Fall back to parsing from title (e.g., "White / S")
                                if (v.title && v.title.includes(' / ')) {
                                    const parts = v.title.split(' / ');
                                    if (parts.length >= 2) {
                                        colors.add(parts[0].trim());
                                        sizes.add(parts[1].trim());
                                    }
                                } else if (v.title) {
                                    // Single option - could be color or size
                                    sizes.add(v.title.trim());
                                }
                            });
                            
                            // Color name to hex mapping for common apparel colors
                            const colorHexMap = {
                                'white': '#FFFFFF', 'black': '#000000', 'navy': '#000080', 'navy blue': '#000080',
                                'red': '#FF0000', 'blue': '#0000FF', 'royal': '#4169E1', 'royal blue': '#4169E1',
                                'green': '#008000', 'forest green': '#228B22', 'kelly green': '#4CBB17',
                                'grey': '#808080', 'gray': '#808080', 'heather grey': '#9FA0A0', 'heather gray': '#9FA0A0',
                                'sport grey': '#8E8E8E', 'dark heather': '#3D3D3D', 'charcoal': '#36454F',
                                'pink': '#FFC0CB', 'light pink': '#FFB6C1', 'hot pink': '#FF69B4',
                                'purple': '#800080', 'maroon': '#800000', 'cardinal red': '#C41E3A',
                                'orange': '#FFA500', 'gold': '#FFD700', 'yellow': '#FFFF00',
                                'brown': '#8B4513', 'chocolate': '#D2691E', 'dark chocolate': '#3D1C02',
                                'tan': '#D2B48C', 'sand': '#C2B280', 'natural': '#F5F5DC', 'cream': '#FFFDD0',
                                'olive': '#808000', 'military green': '#4B5320', 'midnight navy': '#003366',
                                'turquoise': '#40E0D0', 'teal': '#008080', 'cyan': '#00FFFF', 'aqua': '#00FFFF',
                                'indigo': '#4B0082', 'violet': '#EE82EE', 'light blue': '#ADD8E6', 'sky blue': '#87CEEB',
                                'mint': '#98FF98', 'lime': '#00FF00', 'coral': '#FF7F50', 'salmon': '#FA8072',
                                'burgundy': '#800020', 'wine': '#722F37', 'berry': '#8E4585',
                                'silver': '#C0C0C0', 'ash': '#B2BEB5', 'ice grey': '#D6D6D6',
                                'tahiti blue': '#0080A0', 'vibrant yellow': '#FFFF00', 'desert pink': '#EFCDC0'
                            };
                            
                            function getColorHex(colorName) {
                                const lower = colorName.toLowerCase().replace('solid ', '');
                                if (colorHexMap[lower]) return colorHexMap[lower];
                                for (const [key, hex] of Object.entries(colorHexMap)) {
                                    if (lower.includes(key) || key.includes(lower)) return hex;
                                }
                                return '#CCCCCC';
                            }
                            
                            // Show color swatches
                            const uniqueColors = [...colors];
                            if (uniqueColors.length > 0) {
                                document.getElementById('colorSwatches').style.display = 'block';
                                document.getElementById('colorSwatchesGrid').innerHTML = uniqueColors.map(c => {
                                    const hex = getColorHex(c);
                                    const isLight = hex === '#FFFFFF' || hex === '#FFFF00' || hex === '#FFD700' || hex === '#F5F5DC' || hex === '#FFFDD0';
                                    return `
                                    <div style="display: flex; flex-direction: column; align-items: center; width: 70px;">
                                        <div style="width: 40px; height: 40px; border-radius: 50%; background: ${hex}; border: 2px solid ${isLight ? '#ccc' : hex}; box-shadow: 0 2px 4px rgba(0,0,0,0.2);"></div>
                                        <div style="font-size: 10px; text-align: center; margin-top: 4px; line-height: 1.2; max-width: 70px; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(c)}">${escapeHtml(c.replace('Solid ', ''))}</div>
                                    </div>
                                `}).join('');
                            } else {
                                document.getElementById('colorSwatches').style.display = 'none';
                            }
                            
                            // Show size chart
                            const uniqueSizes = [...sizes];
                            if (uniqueSizes.length > 0) {
                                const sizeOrder = ['XS', 'S', 'M', 'L', 'XL', '2XL', '3XL', '4XL', '5XL', '6XL'];
                                uniqueSizes.sort((a, b) => {
                                    const aIdx = sizeOrder.indexOf(a);
                                    const bIdx = sizeOrder.indexOf(b);
                                    if (aIdx !== -1 && bIdx !== -1) return aIdx - bIdx;
                                    if (aIdx !== -1) return -1;
                                    if (bIdx !== -1) return 1;
                                    return a.localeCompare(b);
                                });
                                document.getElementById('sizeChart').style.display = 'block';
                                document.getElementById('sizeChartGrid').innerHTML = uniqueSizes.map(s => `
                                    <div style="background: white; border: 2px solid #1877f2; border-radius: 6px; padding: 8px 16px; font-weight: 600; color: #1877f2; text-align: center; min-width: 50px;">
                                        ${escapeHtml(s)}
                                    </div>
                                `).join('');
                                document.getElementById('printifySizeGuideLink').href = 'https://printify.com/app/products/' + selectedBlueprint;
                            } else {
                                document.getElementById('sizeChart').style.display = 'none';
                            }
                            
                            // Show summary
                            const summaryEl = document.getElementById('variantsSummary');
                            if (summaryEl) summaryEl.style.display = 'block';
                            const variantCountEl = document.getElementById('variantCount');
                            if (variantCountEl) variantCountEl.textContent = allVariants.length;
                            const colorCountEl = document.getElementById('colorCount');
                            if (colorCountEl) colorCountEl.textContent = colors.size;
                            const sizeCountEl = document.getElementById('sizeCount');
                            if (sizeCountEl) sizeCountEl.textContent = sizes.size;
                            const colorsListEl = document.getElementById('colorsList');
                            const sizesListEl = document.getElementById('sizesList');
                            if (colorsListEl) colorsListEl.textContent = colors.size > 0 ? 'Colors: ' + [...colors].join(', ') : '';
                            if (sizesListEl) sizesListEl.textContent = sizes.size > 0 ? 'Sizes: ' + [...sizes].join(', ') : '';
                            
                            document.getElementById('variantsList').innerHTML = allVariants.map(v => {
                                const price = v.cost || v.price || 0;
                                const priceDisplay = price ? '$' + (price / 100).toFixed(2) : '';
                                return `
                                <label style="display: flex; align-items: center; padding: 8px; border-bottom: 1px solid #f0f2f5; cursor: pointer;">
                                    <input type="checkbox" class="variantCheck" value="${v.id}" style="margin-right: 10px;">
                                    <span><strong>${escapeHtml(v.title)}</strong>${priceDisplay ? ' - ' + priceDisplay : ''}</span>
                                </label>
                            `}).join('');
                            
                            document.querySelectorAll('.variantCheck').forEach(cb => {
                                cb.addEventListener('change', updateSelectedCount);
                            });
                            
                            // Auto-select all variants by default for convenience
                            selectAllVariants();
                            
                            document.getElementById('step3').style.display = 'block';
                        })
                        .catch(err => {
                            document.getElementById('variantsList').innerHTML = '<p style="color: #dc3545;">Error: ' + err.message + '</p>';
                        });
                }
                
                function selectAllVariants() {
                    document.querySelectorAll('.variantCheck').forEach(cb => cb.checked = true);
                    updateSelectedCount();
                }
                
                function deselectAllVariants() {
                    document.querySelectorAll('.variantCheck').forEach(cb => cb.checked = false);
                    updateSelectedCount();
                }
                
                function updateSelectedCount() {
                    const count = document.querySelectorAll('.variantCheck:checked').length;
                    document.getElementById('selectedCount').textContent = count + ' selected';
                    const selectedCount2 = document.getElementById('selectedCount2');
                    if (selectedCount2) selectedCount2.textContent = count;
                }
                
                function previewDesign(input) {
                    const preview = document.getElementById('designPreview');
                    const uploadPrompt = document.getElementById('uploadPrompt');
                    const uploadArea = document.getElementById('uploadArea');
                    if (input.files && input.files[0]) {
                        const reader = new FileReader();
                        reader.onload = function(e) {
                            if (preview) {
                                preview.innerHTML = '<img src="' + e.target.result + '" style="max-width: 100%; max-height: 100%; object-fit: contain;">';
                            }
                            // Also update the upload area to show the preview
                            if (uploadPrompt) {
                                uploadPrompt.innerHTML = `
                                    <img src="${e.target.result}" style="max-width: 150px; max-height: 150px; object-fit: contain; border-radius: 8px;">
                                    <div style="font-size: 12px; color: #28a745; margin-top: 8px; font-weight: 600;">${input.files[0].name}</div>
                                    <div style="font-size: 11px; color: #65676b; margin-top: 4px;">Click to change</div>
                                `;
                            }
                            // Update upload area border to green to indicate success
                            if (uploadArea) {
                                uploadArea.style.borderColor = '#28a745';
                            }
                        };
                        reader.readAsDataURL(input.files[0]);
                    }
                }
                
                function handleDesignUpload(input) {
                    // Handle both file selection and cancel
                    if (input.files && input.files[0]) {
                        previewDesign(input);
                    } else {
                        // User cancelled the file picker - reset the preview
                        resetDesignPreview();
                    }
                    updateCreateButtonState();
                }
                
                function resetDesignPreview() {
                    const uploadPrompt = document.getElementById('uploadPrompt');
                    const uploadArea = document.getElementById('uploadArea');
                    if (uploadPrompt) {
                        uploadPrompt.innerHTML = `
                            <div style="font-size: 40px; margin-bottom: 10px;">+</div>
                            <div style="font-weight: 600; color: #1877f2;">Click to upload your design</div>
                            <div style="font-size: 12px; color: #65676b; margin-top: 5px;">PNG with transparent background recommended</div>
                        `;
                    }
                    if (uploadArea) uploadArea.style.borderColor = '#1877f2';
                }
                
                function updateCreateButtonState() {
                    const designFile = document.getElementById('designFile');
                    const createBtn = document.getElementById('createBtn');
                    const createBtnHint = document.getElementById('createBtnHint');
                    
                    if (!createBtn) return;
                    
                    const hasFile = designFile && designFile.files && designFile.files.length > 0 && designFile.files[0];
                    
                    if (hasFile) {
                        createBtn.disabled = false;
                        createBtn.style.background = '#28a745';
                        createBtn.style.cursor = 'pointer';
                        createBtn.style.boxShadow = '0 2px 8px rgba(40,167,69,0.3)';
                        if (createBtnHint) createBtnHint.style.display = 'none';
                    } else {
                        createBtn.disabled = true;
                        createBtn.style.background = '#ccc';
                        createBtn.style.cursor = 'not-allowed';
                        createBtn.style.boxShadow = 'none';
                        if (createBtnHint) createBtnHint.style.display = 'block';
                    }
                }
                
                function backToCatalog() {
                    document.getElementById('catalogContainer').style.display = 'block';
                    document.getElementById('productCreator').style.display = 'none';
                    // Show quick templates again
                    const quickTemplates = document.getElementById('quickTemplates');
                    if (quickTemplates) quickTemplates.style.display = 'block';
                    document.getElementById('variantsSummary').style.display = 'none';
                    document.getElementById('colorSwatches').style.display = 'none';
                    document.getElementById('sizeChart').style.display = 'none';
                    document.getElementById('blueprintImages').style.display = 'none';
                    document.getElementById('blueprintBrandModel').textContent = '';
                    document.getElementById('blueprintImagesGrid').innerHTML = '';
                    document.getElementById('sizeChartGrid').innerHTML = '';
                    document.getElementById('mockupsGrid').innerHTML = '';
                    document.getElementById('productTitle').value = '';
                    document.getElementById('productDescription').value = '';
                    // Reset the design preview
                    const designPreview = document.getElementById('designPreview');
                    if (designPreview) designPreview.innerHTML = '<span style="color: #65676b;">No design uploaded</span>';
                    // Reset the upload prompt
                    const uploadPrompt = document.getElementById('uploadPrompt');
                    if (uploadPrompt) {
                        uploadPrompt.innerHTML = `
                            <div style="font-size: 40px; margin-bottom: 10px;">+</div>
                            <div style="font-weight: 600; color: #1877f2;">Click to upload your design</div>
                            <div style="font-size: 12px; color: #65676b; margin-top: 5px;">PNG with transparent background recommended</div>
                        `;
                    }
                    // Reset file input
                    const designFile = document.getElementById('designFile');
                    if (designFile) designFile.value = '';
                    // Reset upload area border
                    const uploadArea = document.getElementById('uploadArea');
                    if (uploadArea) uploadArea.style.borderColor = '#1877f2';
                    // Reset create button state
                    const createBtn = document.getElementById('createBtn');
                    const createBtnHint = document.getElementById('createBtnHint');
                    if (createBtn) {
                        createBtn.disabled = true;
                        createBtn.style.background = '#ccc';
                        createBtn.style.cursor = 'not-allowed';
                        createBtn.style.boxShadow = 'none';
                    }
                    if (createBtnHint) createBtnHint.style.display = 'block';
                    // Clear status message
                    const createStatus = document.getElementById('createStatus');
                    if (createStatus) createStatus.innerHTML = '';
                    const successDiv = document.getElementById('creationSuccess');
                    if (successDiv) successDiv.style.display = 'none';
                    selectedBlueprint = null;
                    selectedProvider = null;
                    selectedBlueprintTitle = '';
                }
                
                function createProduct() {
                    const title = document.getElementById('productTitle').value.trim();
                    const description = document.getElementById('productDescription').value.trim();
                    const designFile = document.getElementById('designFile').files[0];
                    const autoPublish = document.getElementById('autoPublish').checked;
                    const variantIds = Array.from(document.querySelectorAll('.variantCheck:checked')).map(cb => parseInt(cb.value));
                    
                    if (!title) {
                        alert('Please enter a product title');
                        return;
                    }
                    
                    if (!designFile) {
                        alert('Please upload a design image');
                        return;
                    }
                    
                    if (variantIds.length === 0) {
                        alert('Please select at least one variant (use "Select All" for all sizes/colors)');
                        return;
                    }
                    
                    const btn = document.getElementById('createBtn');
                    const status = document.getElementById('createStatus');
                    btn.disabled = true;
                    btn.textContent = 'Creating...';
                    status.innerHTML = '<div style="display: flex; align-items: center; gap: 10px;"><span class="spinner" style="width: 16px; height: 16px; border: 2px solid #ccc; border-top-color: #1877f2; border-radius: 50%; animation: spin 1s linear infinite;"></span>Uploading your design and creating product...</div><style>@keyframes spin { to { transform: rotate(360deg); } }</style>';
                    
                    const reader = new FileReader();
                    reader.onload = function(e) {
                        const base64 = e.target.result.split(',')[1];
                        
                        fetch('api/publish-to-printify.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                action: 'create_and_publish',
                                title: title,
                                description: description,
                                blueprint_id: selectedBlueprint,
                                print_provider_id: selectedProvider,
                                variant_ids: variantIds,
                                design_base64: base64,
                                design_filename: designFile.name,
                                auto_publish: autoPublish
                            })
                        })
                        .then(r => {
                            if (!r.ok) throw new Error('Server error: ' + r.status);
                            return r.text();
                        })
                        .then(text => {
                            if (!text || text.trim() === '') {
                                throw new Error('Empty response from server. Please try again.');
                            }
                            try {
                                return JSON.parse(text);
                            } catch (e) {
                                console.error('JSON parse error:', text.substring(0, 500));
                                throw new Error('Server returned invalid response. Please check your connection and try again.');
                            }
                        })
                        .then(data => {
                            btn.disabled = false;
                            btn.textContent = 'Create Product';
                            
                            if (data.success) {
                                status.innerHTML = '<span style="color: #28a745; font-weight: 600;">Product created successfully!</span>';
                                
                                // Show success section with mockups
                                document.getElementById('step3').style.display = 'none';
                                document.getElementById('creationSuccess').style.display = 'block';
                                document.getElementById('createdProductId').textContent = data.product_id;
                                
                                // Fetch and display mockups
                                fetchProductMockups(data.product_id);
                            } else {
                                status.innerHTML = '<span style="color: #dc3545;">Error: ' + (data.error || 'Failed to create product. Please try again.') + '</span>';
                            }
                        })
                        .catch(err => {
                            btn.disabled = false;
                            btn.textContent = 'Create Product';
                            status.innerHTML = '<span style="color: #dc3545;">Error: ' + err.message + '</span>';
                        });
                    };
                    reader.readAsDataURL(designFile);
                }
                
                function fetchProductMockups(productId) {
                    const mockupsGrid = document.getElementById('mockupsGrid');
                    const mockupsLoading = document.getElementById('mockupsLoading');
                    mockupsGrid.innerHTML = '';
                    mockupsLoading.style.display = 'block';
                    
                    fetch('api/publish-to-printify.php?action=product&product_id=' + productId)
                        .then(r => {
                            if (!r.ok) throw new Error('Server error: ' + r.status);
                            return r.text();
                        })
                        .then(text => {
                            if (!text || text.trim() === '') {
                                throw new Error('Empty response from server');
                            }
                            try {
                                return JSON.parse(text);
                            } catch (e) {
                                console.error('JSON parse error:', text.substring(0, 200));
                                throw new Error('Invalid server response');
                            }
                        })
                        .then(data => {
                            mockupsLoading.style.display = 'none';
                            
                            // Handle both data.images and data.product.images formats
                            const images = data.images || (data.product && data.product.images) || [];
                            
                            if (images.length > 0) {
                                mockupsGrid.innerHTML = images.map(img => {
                                    const imgSrc = typeof img === 'string' ? img : (img.src || img.url || '');
                                    return `
                                    <div style="background: white; border: 1px solid #e4e6e9; border-radius: 6px; padding: 8px;">
                                        <img src="${imgSrc}" alt="Product mockup" 
                                             style="max-width: 200px; max-height: 200px; object-fit: contain; border-radius: 4px; cursor: pointer;"
                                             onclick="window.open('${imgSrc}', '_blank')">
                                    </div>
                                `}).join('');
                            } else {
                                mockupsGrid.innerHTML = '<p style="color: #65676b;">Mockups are being generated. They may take a few minutes to appear.</p>';
                            }
                        })
                        .catch(err => {
                            mockupsLoading.style.display = 'none';
                            mockupsGrid.innerHTML = '<p style="color: #dc3545;">Error loading mockups: ' + err.message + '</p>';
                        });
                }
                
                function escapeHtml(text) {
                    const div = document.createElement('div');
                    div.textContent = text || '';
                    return div.innerHTML;
                }
                </script>

            <?php elseif ($activeTab === 'digital'): ?>
                <?php
                // Get digital products
                $digitalStmt = $pdo->query("SELECT * FROM products ORDER BY created_at DESC");
                $digitalProducts = $digitalStmt->fetchAll();
                
                // Get digital products in feed
                $digitalFeedStmt = $pdo->query("
                    SELECT fpp.id as feed_post_id, fpp.created_at,
                           p.id as product_id, p.name, p.image_url, p.price, p.product_type
                    FROM feed_product_posts fpp
                    JOIN products p ON fpp.product_id = p.id
                    WHERE fpp.product_type = 'digital'
                    ORDER BY fpp.created_at DESC
                ");
                $digitalFeedPosts = $digitalFeedStmt->fetchAll();
                ?>
                
                <h2>Digital Products (eBooks & Downloads)</h2>
                <p style="color: #65676b; margin-bottom: 20px;">Add and manage digital products like eBooks and downloadable content.</p>
                
                <?php if (isset($_GET['digital_added'])): ?>
                    <div class="alert alert-success">Digital product added successfully!</div>
                <?php endif; ?>
                <?php if (isset($_GET['digital_updated'])): ?>
                    <div class="alert alert-success">Digital product updated successfully!</div>
                <?php endif; ?>
                <?php if (isset($_GET['digital_deleted'])): ?>
                    <div class="alert alert-success">Digital product deleted successfully!</div>
                <?php endif; ?>
                
                <!-- Add New Digital Product -->
                <div style="background: #f0f2f5; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h3 style="margin-top: 0;">Add New Digital Product</h3>
                    <form id="addDigitalForm" enctype="multipart/form-data" style="display: grid; gap: 15px;">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                            <div>
                                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Product Name *</label>
                                <input type="text" id="digitalName" required style="width: 100%; padding: 10px; border: 1px solid #e4e6e9; border-radius: 6px;">
                            </div>
                            <div>
                                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Price ($) *</label>
                                <input type="number" id="digitalPrice" step="0.01" min="0" required style="width: 100%; padding: 10px; border: 1px solid #e4e6e9; border-radius: 6px;">
                            </div>
                        </div>
                        <div>
                            <label style="display: block; margin-bottom: 5px; font-weight: 600;">Description</label>
                            <textarea id="digitalDescription" rows="3" style="width: 100%; padding: 10px; border: 1px solid #e4e6e9; border-radius: 6px;"></textarea>
                        </div>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                            <div>
                                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Cover Image *</label>
                                <input type="file" id="digitalImage" accept="image/*" required style="width: 100%; padding: 10px; border: 1px solid #e4e6e9; border-radius: 6px; background: white;">
                            </div>
                            <div>
                                <label style="display: block; margin-bottom: 5px; font-weight: 600;">PDF/Download File</label>
                                <input type="file" id="digitalFile" accept=".pdf,.epub,.zip" style="width: 100%; padding: 10px; border: 1px solid #e4e6e9; border-radius: 6px; background: white;">
                            </div>
                        </div>
                        <div>
                            <label style="display: block; margin-bottom: 5px; font-weight: 600;">Product Type</label>
                            <select id="digitalType" style="width: 100%; padding: 10px; border: 1px solid #e4e6e9; border-radius: 6px;">
                                <option value="ebook">eBook</option>
                                <option value="pdf">PDF Document</option>
                                <option value="download">Digital Download</option>
                            </select>
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <button type="submit" class="btn btn-primary">Add Product</button>
                        </div>
                    </form>
                </div>
                
                <!-- Digital Products in Feed -->
                <h3>Digital Products in Feed (<?php echo count($digitalFeedPosts); ?>)</h3>
                <?php if (empty($digitalFeedPosts)): ?>
                    <div style="background: #f8f9fa; padding: 30px; border-radius: 8px; text-align: center; color: #65676b; margin-bottom: 30px;">
                        No digital products posted to feed yet.
                    </div>
                <?php else: ?>
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px; margin-bottom: 30px;">
                        <?php foreach ($digitalFeedPosts as $dfp): ?>
                            <div style="border: 1px solid #e4e6e9; border-radius: 8px; padding: 12px; text-align: center; background: white;">
                                <img src="<?php echo h($dfp['image_url']); ?>" alt="<?php echo h($dfp['name']); ?>" 
                                     style="max-width: 100%; height: 100px; object-fit: contain; margin-bottom: 8px;">
                                <h4 style="margin: 0 0 4px 0; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;"><?php echo h($dfp['name']); ?></h4>
                                <p style="margin: 0 0 8px 0; font-size: 11px; color: #42b72a; font-weight: 600;">$<?php echo number_format($dfp['price'], 2); ?></p>
                                <button onclick="removeDigitalFromFeed(<?php echo $dfp['feed_post_id']; ?>)" 
                                        style="padding: 5px 12px; background: #e41e3f; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 11px;">
                                    Remove from Feed
                                </button>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                
                <hr style="border: none; border-top: 1px solid #e4e6e9; margin: 30px 0;">
                
                <!-- All Digital Products -->
                <h3>All Digital Products (<?php echo count($digitalProducts); ?>)</h3>
                <?php if (empty($digitalProducts)): ?>
                    <p style="text-align: center; padding: 40px; color: #65676b;">No digital products yet. Use the form above to add one.</p>
                <?php else: ?>
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px;">
                        <?php foreach ($digitalProducts as $dp): ?>
                            <div style="border: 1px solid #e4e6e9; border-radius: 8px; padding: 15px; text-align: center; background: white;">
                                <?php if ($dp['image_url']): ?>
                                    <img src="<?php echo h($dp['image_url']); ?>" alt="<?php echo h($dp['name']); ?>" 
                                         style="max-width: 100%; height: 150px; object-fit: contain; margin-bottom: 10px;">
                                <?php else: ?>
                                    <div style="height: 150px; display: flex; align-items: center; justify-content: center; background: #f0f2f5; border-radius: 4px; margin-bottom: 10px;">
                                        <span style="color: #65676b;">No Image</span>
                                    </div>
                                <?php endif; ?>
                                <h4 style="margin: 0 0 5px 0; font-size: 14px;"><?php echo h($dp['name']); ?></h4>
                                <p style="margin: 0; color: #42b72a; font-weight: 600;">$<?php echo number_format($dp['price'], 2); ?></p>
                                <p style="margin: 5px 0 0 0; color: #65676b; font-size: 12px;">
                                    <?php echo ucfirst($dp['product_type'] ?? 'ebook'); ?>
                                    <?php if (!$dp['is_active']): ?><span style="color: #e41e3f;"> (Inactive)</span><?php endif; ?>
                                </p>
                                <div style="margin-top: 10px; display: flex; gap: 8px; justify-content: center; flex-wrap: wrap;">
                                    <button onclick="postDigitalToFeed(<?php echo $dp['id']; ?>, '<?php echo h(addslashes($dp['name'])); ?>')" 
                                            style="padding: 6px 12px; background: #42b72a; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">
                                        Post to Feed
                                    </button>
                                    <button onclick="editDigitalProduct(<?php echo $dp['id']; ?>)" 
                                            style="padding: 6px 12px; background: #1877f2; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">
                                        Edit
                                    </button>
                                    <button onclick="deleteDigitalProduct(<?php echo $dp['id']; ?>, '<?php echo h(addslashes($dp['name'])); ?>')" 
                                            style="padding: 6px 12px; background: #e41e3f; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">
                                        Delete
                                    </button>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                
                <script>
                document.getElementById('addDigitalForm').addEventListener('submit', async function(e) {
                    e.preventDefault();
                    
                    const formData = new FormData();
                    formData.append('action', 'add');
                    formData.append('name', document.getElementById('digitalName').value);
                    formData.append('price', document.getElementById('digitalPrice').value);
                    formData.append('description', document.getElementById('digitalDescription').value);
                    formData.append('product_type', document.getElementById('digitalType').value);
                    
                    const imageFile = document.getElementById('digitalImage').files[0];
                    if (imageFile) formData.append('image', imageFile);
                    
                    const pdfFile = document.getElementById('digitalFile').files[0];
                    if (pdfFile) formData.append('pdf_file', pdfFile);
                    
                    try {
                        const response = await fetch('api/digital-products.php', {
                            method: 'POST',
                            body: formData
                        });
                        const data = await response.json();
                        if (data.success) {
                            window.location.href = 'admin.php?tab=digital&digital_added=1';
                        } else {
                            alert(data.error || 'Failed to add product');
                        }
                    } catch (err) {
                        console.error('Add product error:', err);
                        alert('Failed to add product. Please try again.');
                    }
                });
                
                function postDigitalToFeed(productId, productName) {
                    if (!confirm('Post "' + productName + '" to the community feed?')) return;
                    
                    fetch('api/feed-products.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({action: 'post_digital', product_id: productId})
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            window.location.reload();
                        } else {
                            alert(data.error || 'Failed to post to feed');
                        }
                    })
                    .catch(err => {
                        console.error('Post to feed error:', err);
                        alert('Failed to post to feed');
                    });
                }
                
                function removeDigitalFromFeed(feedPostId) {
                    if (!confirm('Remove this product from the community feed?')) return;
                    
                    fetch('api/feed-products.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({action: 'remove', feed_post_id: feedPostId})
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            window.location.reload();
                        } else {
                            alert(data.error || 'Failed to remove from feed');
                        }
                    });
                }
                
                function editDigitalProduct(productId) {
                    fetch('api/digital-products.php?action=get&id=' + productId)
                        .then(r => r.json())
                        .then(data => {
                            if (data.success) {
                                const p = data.product;
                                document.getElementById('editDigitalId').value = p.id;
                                document.getElementById('editDigitalName').value = p.name || '';
                                document.getElementById('editDigitalPrice').value = p.price || '';
                                document.getElementById('editDigitalDescription').value = p.description || '';
                                document.getElementById('editDigitalType').value = p.product_type || 'ebook';
                                document.getElementById('editDigitalActive').checked = p.is_active;
                                document.getElementById('editDigitalModal').style.display = 'flex';
                            } else {
                                alert('Failed to load product');
                            }
                        });
                }
                
                function closeEditDigitalModal() {
                    document.getElementById('editDigitalModal').style.display = 'none';
                }
                
                function saveDigitalEdit() {
                    const formData = new FormData();
                    formData.append('action', 'update');
                    formData.append('id', document.getElementById('editDigitalId').value);
                    formData.append('name', document.getElementById('editDigitalName').value);
                    formData.append('price', document.getElementById('editDigitalPrice').value);
                    formData.append('description', document.getElementById('editDigitalDescription').value);
                    formData.append('product_type', document.getElementById('editDigitalType').value);
                    formData.append('is_active', document.getElementById('editDigitalActive').checked ? '1' : '0');
                    
                    const newImage = document.getElementById('editDigitalImage').files[0];
                    if (newImage) formData.append('image', newImage);
                    
                    fetch('api/digital-products.php', {
                        method: 'POST',
                        body: formData
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            window.location.href = 'admin.php?tab=digital&digital_updated=1';
                        } else {
                            alert(data.error || 'Failed to update product');
                        }
                    });
                }
                
                function deleteDigitalProduct(productId, productName) {
                    if (!confirm('Delete "' + productName + '"? This cannot be undone.')) return;
                    
                    fetch('api/digital-products.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({action: 'delete', id: productId})
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            window.location.href = 'admin.php?tab=digital&digital_deleted=1';
                        } else {
                            alert(data.error || 'Failed to delete product');
                        }
                    });
                }
                </script>
                
                <!-- Edit Digital Product Modal -->
                <div id="editDigitalModal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; align-items: center; justify-content: center;">
                    <div style="background: white; padding: 30px; border-radius: 12px; max-width: 500px; width: 90%;">
                        <h3 style="margin: 0 0 20px 0;">Edit Digital Product</h3>
                        <input type="hidden" id="editDigitalId">
                        <div style="display: grid; gap: 15px;">
                            <div>
                                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Name</label>
                                <input type="text" id="editDigitalName" style="width: 100%; padding: 10px; border: 1px solid #e4e6e9; border-radius: 6px;">
                            </div>
                            <div>
                                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Price ($)</label>
                                <input type="number" id="editDigitalPrice" step="0.01" style="width: 100%; padding: 10px; border: 1px solid #e4e6e9; border-radius: 6px;">
                            </div>
                            <div>
                                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Description</label>
                                <textarea id="editDigitalDescription" rows="3" style="width: 100%; padding: 10px; border: 1px solid #e4e6e9; border-radius: 6px;"></textarea>
                            </div>
                            <div>
                                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Product Type</label>
                                <select id="editDigitalType" style="width: 100%; padding: 10px; border: 1px solid #e4e6e9; border-radius: 6px;">
                                    <option value="ebook">eBook</option>
                                    <option value="pdf">PDF Document</option>
                                    <option value="download">Digital Download</option>
                                </select>
                            </div>
                            <div>
                                <label style="display: block; margin-bottom: 5px; font-weight: 600;">Replace Cover Image</label>
                                <input type="file" id="editDigitalImage" accept="image/*" style="width: 100%; padding: 10px; border: 1px solid #e4e6e9; border-radius: 6px; background: white;">
                            </div>
                            <div>
                                <label style="display: flex; align-items: center; gap: 8px;">
                                    <input type="checkbox" id="editDigitalActive">
                                    <span>Active (visible in shop)</span>
                                </label>
                            </div>
                        </div>
                        <div style="display: flex; gap: 10px; justify-content: flex-end; margin-top: 20px;">
                            <button onclick="closeEditDigitalModal()" style="padding: 10px 20px; border: 1px solid #e4e6e9; background: white; border-radius: 6px; cursor: pointer;">Cancel</button>
                            <button onclick="saveDigitalEdit()" style="padding: 10px 20px; background: #1877f2; color: white; border: none; border-radius: 6px; cursor: pointer;">Save Changes</button>
                        </div>
                    </div>
                </div>

            <?php elseif ($activeTab === 'backgrounds'): ?>
                <?php
                // Get categories and images
                $categoriesStmt = $pdo->query("SELECT * FROM background_categories ORDER BY sort_order, name");
                $bgCategories = $categoriesStmt->fetchAll();
                
                $imagesStmt = $pdo->query("SELECT bi.*, bc.name as category_name FROM background_images bi JOIN background_categories bc ON bi.category_id = bc.id ORDER BY bi.category_id, bi.sort_order");
                $bgImages = $imagesStmt->fetchAll();
                ?>
                
                <h2>Background Management</h2>
                <p style="color: #65676b; margin-bottom: 20px;">Manage background images and categories for user customization.</p>

                <?php if (isset($_GET['bg_success'])): ?>
                    <div class="alert alert-success">Background saved successfully!</div>
                <?php endif; ?>
                <?php if (isset($_GET['cat_success'])): ?>
                    <div class="alert alert-success">Category saved successfully!</div>
                <?php endif; ?>
                <?php if (isset($_GET['bg_deleted'])): ?>
                    <div class="alert alert-success">Background deleted successfully!</div>
                <?php endif; ?>
                <?php if (isset($_GET['cat_deleted'])): ?>
                    <div class="alert alert-success">Category deleted successfully!</div>
                <?php endif; ?>

                <!-- Category Management -->
                <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h3 style="margin-top: 0;">Categories</h3>
                    <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 15px;">
                        <?php foreach ($bgCategories as $cat): ?>
                            <div style="background: white; padding: 10px 15px; border-radius: 6px; display: flex; align-items: center; gap: 10px; border: 1px solid #e4e6e9;">
                                <span><?php echo h($cat['name']); ?></span>
                                <button onclick="editCategory(<?php echo $cat['id']; ?>, '<?php echo h(addslashes($cat['name'])); ?>')" style="background: none; border: none; color: #1877f2; cursor: pointer; font-size: 12px;">Edit</button>
                                <button onclick="deleteCategory(<?php echo $cat['id']; ?>)" style="background: none; border: none; color: #e41e3f; cursor: pointer; font-size: 12px;">Delete</button>
                            </div>
                        <?php endforeach; ?>
                    </div>
                    <div style="display: flex; gap: 10px; align-items: center;">
                        <input type="text" id="newCategoryName" placeholder="New category name..." style="padding: 10px; border: 1px solid #e4e6e9; border-radius: 6px; flex: 1; max-width: 300px;">
                        <button onclick="addCategory()" class="btn btn-primary">Add Category</button>
                    </div>
                </div>

                <!-- Image Upload -->
                <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h3 style="margin-top: 0;">Upload New Background</h3>
                    <form id="uploadBgForm" enctype="multipart/form-data" style="display: flex; flex-wrap: wrap; gap: 15px; align-items: flex-end;">
                        <div style="flex: 1; min-width: 200px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 600;">Title</label>
                            <input type="text" name="title" required placeholder="Background title..." style="width: 100%; padding: 10px; border: 1px solid #e4e6e9; border-radius: 6px;">
                        </div>
                        <div style="min-width: 150px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 600;">Category</label>
                            <select name="category_id" required style="width: 100%; padding: 10px; border: 1px solid #e4e6e9; border-radius: 6px;">
                                <option value="">Select category...</option>
                                <?php foreach ($bgCategories as $cat): ?>
                                    <option value="<?php echo $cat['id']; ?>"><?php echo h($cat['name']); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div style="min-width: 200px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 600;">Image File</label>
                            <input type="file" name="image" required accept="image/*" style="width: 100%; padding: 8px; border: 1px solid #e4e6e9; border-radius: 6px; background: white;">
                        </div>
                        <button type="submit" class="btn btn-primary">Upload</button>
                    </form>
                </div>

                <!-- Image Grid by Category -->
                <?php 
                $imagesByCategory = [];
                foreach ($bgImages as $img) {
                    $imagesByCategory[$img['category_id']][] = $img;
                }
                ?>
                
                <?php foreach ($bgCategories as $cat): ?>
                    <div style="margin-bottom: 30px;">
                        <h3><?php echo h($cat['name']); ?></h3>
                        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 15px;">
                            <?php if (isset($imagesByCategory[$cat['id']])): ?>
                                <?php foreach ($imagesByCategory[$cat['id']] as $img): ?>
                                    <div style="position: relative; border: 1px solid #e4e6e9; border-radius: 8px; overflow: hidden;">
                                        <img src="<?php echo h(getBackgroundImageUrl($img['thumb_path'])); ?>" alt="<?php echo h($img['title']); ?>" 
                                             style="width: 100%; height: 100px; object-fit: cover;">
                                        <div style="padding: 8px;">
                                            <div style="font-size: 12px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;"><?php echo h($img['title']); ?></div>
                                            <button onclick="deleteBackground(<?php echo $img['id']; ?>)" style="margin-top: 5px; background: none; border: none; color: #e41e3f; cursor: pointer; font-size: 11px;">Delete</button>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <p style="color: #65676b; font-size: 14px;">No backgrounds in this category yet.</p>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endforeach; ?>

                <script>
                function addCategory() {
                    const name = document.getElementById('newCategoryName').value.trim();
                    if (!name) { alert('Please enter a category name'); return; }
                    
                    fetch('api/admin-backgrounds.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({action: 'add_category', name: name})
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            window.location.href = 'admin.php?tab=backgrounds&cat_success=1';
                        } else {
                            alert(data.error || 'Failed to add category');
                        }
                    });
                }
                
                function editCategory(id, currentName) {
                    const newName = prompt('Enter new category name:', currentName);
                    if (!newName || newName === currentName) return;
                    
                    fetch('api/admin-backgrounds.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({action: 'update_category', id: id, name: newName})
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            window.location.href = 'admin.php?tab=backgrounds&cat_success=1';
                        } else {
                            alert(data.error || 'Failed to update category');
                        }
                    });
                }
                
                function deleteCategory(id) {
                    if (!confirm('Delete this category and all its backgrounds?')) return;
                    
                    fetch('api/admin-backgrounds.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({action: 'delete_category', id: id})
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            window.location.href = 'admin.php?tab=backgrounds&cat_deleted=1';
                        } else {
                            alert(data.error || 'Failed to delete category');
                        }
                    });
                }
                
                function deleteBackground(id) {
                    if (!confirm('Delete this background image?')) return;
                    
                    fetch('api/admin-backgrounds.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({action: 'delete_image', id: id})
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            window.location.href = 'admin.php?tab=backgrounds&bg_deleted=1';
                        } else {
                            alert(data.error || 'Failed to delete background');
                        }
                    });
                }
                
                document.getElementById('uploadBgForm').addEventListener('submit', function(e) {
                    e.preventDefault();
                    const formData = new FormData(this);
                    formData.append('action', 'upload_image');
                    
                    fetch('api/admin-backgrounds.php', {
                        method: 'POST',
                        body: formData
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            window.location.href = 'admin.php?tab=backgrounds&bg_success=1';
                        } else {
                            alert(data.error || 'Failed to upload background');
                        }
                    });
                });
                </script>

            <?php elseif ($activeTab === 'interactions'): ?>
                <h2>Manage Interaction Types</h2>
                <p>Add interaction types (flirt, kiss, hug, etc.) that users can send to each other. Upload icons and manage display order.</p>
                
                <?php if (isset($_GET['int_success'])): ?>
                    <div class="alert alert-success">Interaction type saved successfully!</div>
                <?php endif; ?>
                <?php if (isset($_GET['int_reset'])): ?>
                    <div class="alert alert-success">Interaction types reset to bundled defaults!</div>
                <?php endif; ?>
                
                <div style="margin-bottom: 15px; padding: 12px; background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px;">
                    <strong>Icons not showing?</strong> If icons disappeared after a republish, click the button below to restore working defaults.
                    <button onclick="resetToDefaults()" class="btn" style="margin-left: 10px; background: #dc3545; color: white;">Reset to Bundled Defaults</button>
                </div>
                
                <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 20px; margin-top: 20px;">
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 8px;">
                        <h3 style="margin-top: 0;">Add New Type</h3>
                        <form id="addInteractionForm" enctype="multipart/form-data">
                            <div class="form-group">
                                <label>Type Key (lowercase, no spaces)</label>
                                <input type="text" name="type_key" id="typeKey" required pattern="[a-z0-9_]+" placeholder="e.g., flirt, high_five">
                            </div>
                            <div class="form-group">
                                <label>Display Label</label>
                                <input type="text" name="label" id="typeLabel" required placeholder="e.g., Flirt, High Five">
                            </div>
                            <div class="form-group">
                                <label>Icon (64x64 recommended)</label>
                                <input type="file" name="icon" id="typeIcon" accept="image/*">
                                <div id="iconPreview" style="margin-top: 10px; display: none;">
                                    <img id="iconPreviewImg" style="max-width: 64px; max-height: 64px; border: 1px solid #ddd; border-radius: 4px;">
                                </div>
                            </div>
                            <div class="form-group">
                                <label>
                                    <input type="checkbox" name="is_main" id="isMain" value="1"> Show in main row (unchecked = "More" menu)
                                </label>
                            </div>
                            <button type="submit" class="btn btn-primary">Add Type</button>
                        </form>
                    </div>
                    
                    <div>
                        <h3 style="margin-top: 0;">Main Interactions (Always Visible)</h3>
                        <div id="mainInteractions" class="interaction-list" style="min-height: 100px; background: #e8f5e9; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                            <p class="loading-msg" style="color: #666;">Loading...</p>
                        </div>
                        
                        <h3>Extra Interactions ("More" Menu)</h3>
                        <div id="extrasInteractions" class="interaction-list" style="min-height: 100px; background: #fff3e0; padding: 15px; border-radius: 8px;">
                            <p class="loading-msg" style="color: #666;">Loading...</p>
                        </div>
                    </div>
                </div>
                
                <div id="editInteractionModal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; align-items: center; justify-content: center;">
                    <div style="background: white; padding: 25px; border-radius: 12px; max-width: 400px; width: 90%;">
                        <h3 style="margin-top: 0;">Edit Interaction Type</h3>
                        <form id="editInteractionForm" enctype="multipart/form-data">
                            <input type="hidden" name="id" id="editId">
                            <div class="form-group">
                                <label>Display Label</label>
                                <input type="text" name="label" id="editLabel" required>
                            </div>
                            <div class="form-group">
                                <label>Current Icon</label>
                                <div id="editCurrentIcon" style="margin-bottom: 10px;"></div>
                                <label>Replace Icon (optional)</label>
                                <input type="file" name="icon" id="editIcon" accept="image/*">
                            </div>
                            <div class="form-group">
                                <label>
                                    <input type="checkbox" name="is_main" id="editIsMain" value="1"> Show in main row
                                </label>
                            </div>
                            <div style="display: flex; gap: 10px; margin-top: 20px;">
                                <button type="submit" class="btn btn-primary">Save Changes</button>
                                <button type="button" class="btn btn-secondary" onclick="closeEditModal()">Cancel</button>
                            </div>
                        </form>
                    </div>
                </div>
                
                <style>
                .interaction-item {
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    padding: 10px;
                    background: white;
                    border-radius: 8px;
                    margin-bottom: 8px;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                }
                .interaction-item img {
                    width: 40px;
                    height: 40px;
                    object-fit: contain;
                }
                .interaction-item .info {
                    flex: 1;
                }
                .interaction-item .type-key {
                    font-size: 12px;
                    color: #666;
                }
                .interaction-item .actions {
                    display: flex;
                    gap: 8px;
                }
                .interaction-item .actions button {
                    padding: 4px 8px;
                    font-size: 12px;
                }
                .interaction-item.disabled {
                    opacity: 0.5;
                }
                </style>
                
                <script>
                let interactionTypes = { main: [], extras: [] };
                
                document.addEventListener('DOMContentLoaded', function() {
                    loadInteractionTypes();
                    
                    document.getElementById('typeKey').addEventListener('input', function(e) {
                        this.value = this.value.toLowerCase().replace(/[^a-z0-9_]/g, '');
                    });
                    
                    document.getElementById('typeIcon').addEventListener('change', function(e) {
                        const file = e.target.files[0];
                        if (file) {
                            const reader = new FileReader();
                            reader.onload = function(e) {
                                document.getElementById('iconPreviewImg').src = e.target.result;
                                document.getElementById('iconPreview').style.display = 'block';
                            };
                            reader.readAsDataURL(file);
                        }
                    });
                    
                    document.getElementById('addInteractionForm').addEventListener('submit', async function(e) {
                        e.preventDefault();
                        
                        const typeKey = document.getElementById('typeKey').value;
                        const label = document.getElementById('typeLabel').value;
                        const isMain = document.getElementById('isMain').checked;
                        const iconFile = document.getElementById('typeIcon').files[0];
                        
                        let iconPath = '';
                        if (iconFile) {
                            iconPath = await uploadIcon(iconFile);
                            if (!iconPath) return;
                        }
                        
                        const response = await fetch('api/interaction-types.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                action: 'add',
                                type_key: typeKey,
                                label: label,
                                icon_path: iconPath,
                                is_main: isMain
                            })
                        });
                        
                        const data = await response.json();
                        if (data.success) {
                            window.location.href = 'admin.php?tab=interactions&int_success=1';
                        } else {
                            alert(data.error || 'Failed to add interaction type');
                        }
                    });
                    
                    document.getElementById('editInteractionForm').addEventListener('submit', async function(e) {
                        e.preventDefault();
                        
                        const id = document.getElementById('editId').value;
                        const label = document.getElementById('editLabel').value;
                        const isMain = document.getElementById('editIsMain').checked;
                        const iconFile = document.getElementById('editIcon').files[0];
                        
                        let updateData = {
                            action: 'update',
                            id: id,
                            label: label,
                            is_main: isMain
                        };
                        
                        if (iconFile) {
                            const iconPath = await uploadIcon(iconFile);
                            if (iconPath) {
                                updateData.icon_path = iconPath;
                            }
                        }
                        
                        const response = await fetch('api/interaction-types.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(updateData)
                        });
                        
                        const data = await response.json();
                        if (data.success) {
                            window.location.href = 'admin.php?tab=interactions&int_success=1';
                        } else {
                            alert(data.error || 'Failed to update interaction type');
                        }
                    });
                });
                
                async function uploadIcon(file) {
                    const formData = new FormData();
                    formData.append('action', 'upload_icon');
                    formData.append('icon', file);
                    
                    try {
                        const response = await fetch('api/interaction-icons.php', {
                            method: 'POST',
                            body: formData
                        });
                        const data = await response.json();
                        if (data.success) {
                            return data.path;
                        } else {
                            alert(data.error || 'Failed to upload icon');
                            return null;
                        }
                    } catch (err) {
                        alert('Failed to upload icon');
                        return null;
                    }
                }
                
                async function loadInteractionTypes() {
                    try {
                        const response = await fetch('api/interaction-types.php?all=1');
                        const data = await response.json();
                        
                        if (data.success) {
                            interactionTypes = data;
                            renderInteractions('main', data.main, 'mainInteractions');
                            renderInteractions('extras', data.extras, 'extrasInteractions');
                        }
                    } catch (err) {
                        console.error('Failed to load interaction types:', err);
                    }
                }
                
                function renderInteractions(type, items, containerId) {
                    const container = document.getElementById(containerId);
                    container.innerHTML = '';
                    
                    if (items.length === 0) {
                        container.innerHTML = '<p style="color: #666; margin: 0;">No interaction types yet. Add one using the form.</p>';
                        return;
                    }
                    
                    items.forEach(item => {
                        const div = document.createElement('div');
                        div.className = 'interaction-item' + (item.enabled ? '' : ' disabled');
                        div.innerHTML = `
                            <img src="${item.icon_path || '/assets/interactions/default.svg'}" alt="${item.label}" onerror="if(!this.dataset.fallback){this.dataset.fallback='1';this.src='/assets/interactions/default.svg'}">
                            <div class="info">
                                <strong>${item.label}</strong>
                                <div class="type-key">${item.type_key}</div>
                            </div>
                            <div class="actions">
                                <button class="btn btn-secondary" onclick="editInteraction(${item.id})">Edit</button>
                                <button class="btn ${item.enabled ? 'btn-secondary' : 'btn-success'}" onclick="toggleInteraction(${item.id})">
                                    ${item.enabled ? 'Disable' : 'Enable'}
                                </button>
                                <button class="btn btn-danger" onclick="deleteInteraction(${item.id}, '${item.label}')">Delete</button>
                            </div>
                        `;
                        container.appendChild(div);
                    });
                }
                
                function editInteraction(id) {
                    const allItems = [...interactionTypes.main, ...interactionTypes.extras];
                    const item = allItems.find(i => i.id == id);
                    if (!item) return;
                    
                    document.getElementById('editId').value = item.id;
                    document.getElementById('editLabel').value = item.label;
                    document.getElementById('editIsMain').checked = item.is_main;
                    document.getElementById('editCurrentIcon').innerHTML = item.icon_path 
                        ? `<img src="${item.icon_path}" style="max-width: 64px; max-height: 64px;">`
                        : '<span style="color: #666;">No icon</span>';
                    
                    document.getElementById('editInteractionModal').style.display = 'flex';
                }
                
                function closeEditModal() {
                    document.getElementById('editInteractionModal').style.display = 'none';
                }
                
                async function toggleInteraction(id) {
                    try {
                        const response = await fetch('api/interaction-types.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'toggle', id: id })
                        });
                        const data = await response.json();
                        if (data.success) {
                            loadInteractionTypes();
                        }
                    } catch (err) {
                        alert('Failed to toggle interaction type');
                    }
                }
                
                async function resetToDefaults() {
                    if (!confirm('This will DELETE all current interaction types and restore the bundled defaults. Continue?')) {
                        return;
                    }
                    
                    try {
                        const response = await fetch('api/interaction-types.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'reset_defaults' })
                        });
                        const data = await response.json();
                        if (data.success) {
                            window.location.href = 'admin.php?tab=interactions&int_reset=1';
                        } else {
                            alert(data.error || 'Failed to reset');
                        }
                    } catch (err) {
                        alert('Failed to reset interaction types');
                    }
                }
                
                async function deleteInteraction(id, label) {
                    if (!confirm(`Delete "${label}"? This won't delete historical records, but users won't be able to send this type anymore.`)) {
                        return;
                    }
                    
                    try {
                        const response = await fetch('api/interaction-types.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'delete', id: id })
                        });
                        const data = await response.json();
                        if (data.success) {
                            loadInteractionTypes();
                        } else {
                            alert(data.error || 'Failed to delete');
                        }
                    } catch (err) {
                        alert('Failed to delete interaction type');
                    }
                }
                </script>

            <?php elseif ($activeTab === 'carousels'): ?>
                <h2>Feed Carousels</h2>
                <p style="color: #65676b; margin-bottom: 20px;">
                    Manage horizontal scrolling rows that appear in the community feed. Set where each carousel appears (after X posts) and enable/disable as needed.
                </p>

                <div style="background: #f0f2f5; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h3 style="margin-top: 0;">Add New Carousel</h3>
                    <div style="display: grid; grid-template-columns: 1fr 1fr 1fr auto; gap: 15px; align-items: end;">
                        <div class="form-group" style="margin-bottom: 0;">
                            <label for="carouselType">Type</label>
                            <select id="carouselType" onchange="toggleCustomInfo()">
                                <option value="products">Products (Merchandise)</option>
                                <option value="friends">People You May Know</option>
                                <option value="news">News Highlights</option>
                                <option value="groups">Groups to Join</option>
                                <option value="custom">Custom (Upload Your Own)</option>
                            </select>
                            <p id="customTypeInfo" style="display: none; font-size: 12px; color: #1877f2; margin-top: 4px;">
                                After adding, click "Manage Items" to upload content
                            </p>
                        </div>
                        <div class="form-group" style="margin-bottom: 0;">
                            <label for="carouselTitle">Title</label>
                            <input type="text" id="carouselTitle" placeholder="e.g., Check Out Our Merch">
                        </div>
                        <div class="form-group" style="margin-bottom: 0;">
                            <label for="carouselPosition">After Post #</label>
                            <input type="number" id="carouselPosition" value="5" min="1" max="50" title="Position in feed">
                        </div>
                        <div class="form-group" style="margin-bottom: 0;">
                            <label for="carouselHours">Hours Between</label>
                            <input type="number" id="carouselHours" value="24" min="1" max="168" title="Hours between showings">
                        </div>
                        <div class="form-group" style="margin-bottom: 0;">
                            <label for="carouselMinPosts">Min Posts</label>
                            <input type="number" id="carouselMinPosts" value="5" min="1" max="50" title="Minimum new posts required">
                        </div>
                        <button type="button" class="btn btn-primary" onclick="addCarousel()">Add Carousel</button>
                    </div>
                </div>

                <h3>Active Carousels</h3>
                <div id="carouselsList" style="min-height: 100px;">
                    <p style="text-align: center; color: #65676b; padding: 20px;">Loading...</p>
                </div>

                <style>
                    .carousel-card {
                        background: white;
                        border: 1px solid #e4e6e9;
                        border-radius: 8px;
                        padding: 15px 20px;
                        margin-bottom: 10px;
                        display: flex;
                        align-items: center;
                        gap: 20px;
                        transition: box-shadow 0.2s;
                    }
                    .carousel-card:hover {
                        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    }
                    .carousel-card.disabled {
                        opacity: 0.6;
                        background: #f9f9f9;
                    }
                    .carousel-icon {
                        width: 50px;
                        height: 50px;
                        border-radius: 10px;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        font-size: 24px;
                        flex-shrink: 0;
                    }
                    .carousel-icon.products { background: linear-gradient(135deg, #ed8936, #dd6b20); }
                    .carousel-icon.friends { background: linear-gradient(135deg, #1a365d, #2c5282); }
                    .carousel-icon.news { background: linear-gradient(135deg, #1877f2, #1a365d); }
                    .carousel-icon.groups { background: linear-gradient(135deg, #38a169, #276749); }
                    .carousel-icon.custom { background: linear-gradient(135deg, #9f7aea, #6b46c1); }
                    .carousel-info {
                        flex: 1;
                    }
                    .carousel-info h4 {
                        margin: 0 0 4px 0;
                        font-size: 16px;
                    }
                    .carousel-info p {
                        margin: 0;
                        color: #65676b;
                        font-size: 13px;
                    }
                    .carousel-settings {
                        display: flex;
                        flex-wrap: wrap;
                        gap: 8px;
                    }
                    .setting-row {
                        display: flex;
                        flex-direction: column;
                        align-items: center;
                        background: #f0f2f5;
                        padding: 6px 10px;
                        border-radius: 6px;
                        min-width: 70px;
                    }
                    .setting-row span {
                        font-size: 10px;
                        color: #65676b;
                        margin-bottom: 4px;
                    }
                    .setting-row input {
                        width: 50px;
                        padding: 4px;
                        border: 1px solid #ddd;
                        border-radius: 4px;
                        text-align: center;
                        font-size: 13px;
                    }
                    .carousel-status {
                        font-size: 11px;
                        margin-top: 4px;
                        padding: 2px 8px;
                        border-radius: 10px;
                        display: inline-block;
                    }
                    .carousel-status.eligible {
                        background: #d4edda;
                        color: #155724;
                    }
                    .carousel-status.waiting {
                        background: #fff3cd;
                        color: #856404;
                    }
                    .carousel-actions {
                        display: flex;
                        flex-wrap: wrap;
                        gap: 6px;
                    }
                    .carousel-actions .btn {
                        padding: 6px 12px;
                        font-size: 12px;
                    }
                </style>

                <script>
                let carousels = [];
                
                async function loadCarousels() {
                    try {
                        const response = await fetch('api/feed-carousels.php');
                        const data = await response.json();
                        if (data.success) {
                            carousels = data.carousels;
                            renderCarousels();
                        }
                    } catch (error) {
                        console.error('Failed to load carousels:', error);
                    }
                }
                
                function toggleCustomInfo() {
                    const type = document.getElementById('carouselType').value;
                    document.getElementById('customTypeInfo').style.display = type === 'custom' ? 'block' : 'none';
                }
                
                function getCarouselIcon(type) {
                    switch(type) {
                        case 'products': return '🛍️';
                        case 'friends': return '👥';
                        case 'news': return '📰';
                        case 'groups': return '👥';
                        case 'custom': return '✨';
                        default: return '📋';
                    }
                }
                
                function getCarouselTypeName(type) {
                    switch(type) {
                        case 'products': return 'Products Carousel';
                        case 'friends': return 'People You May Know';
                        case 'news': return 'News Highlights';
                        case 'groups': return 'Groups to Join';
                        case 'custom': return 'Custom Carousel';
                        default: return type;
                    }
                }
                
                function renderCarousels() {
                    const container = document.getElementById('carouselsList');
                    
                    if (carousels.length === 0) {
                        container.innerHTML = '<p style="text-align: center; color: #65676b; padding: 40px;">No carousels configured yet. Add one above!</p>';
                        return;
                    }
                    
                    container.innerHTML = carousels.map(c => `
                        <div class="carousel-card ${c.is_active ? '' : 'disabled'}" data-id="${c.id}">
                            <div class="carousel-icon ${c.carousel_type}">${getCarouselIcon(c.carousel_type)}</div>
                            <div class="carousel-info">
                                <h4>${c.title}</h4>
                                <p>${getCarouselTypeName(c.carousel_type)}</p>
                                <div class="carousel-status ${c.is_eligible ? 'eligible' : 'waiting'}">
                                    ${c.is_eligible ? '✓ Ready to show' : '⏳ Waiting'}
                                    ${c.posts_since_last_show !== undefined ? ` (${c.posts_since_last_show} posts since last)` : ''}
                                </div>
                            </div>
                            <div class="carousel-settings">
                                <div class="setting-row">
                                    <span>Position</span>
                                    <input type="number" value="${c.position_after}" min="0" max="50" 
                                           onchange="updatePosition(${c.id}, this.value)" title="Show after post # (0 = top)">
                                </div>
                                <div class="setting-row">
                                    <span>Hours</span>
                                    <input type="number" value="${c.rotation_interval_hours || 24}" min="1" max="168" 
                                           onchange="updateRotation(${c.id}, this.value, null)" title="Hours between showings">
                                </div>
                                <div class="setting-row">
                                    <span>Min Posts</span>
                                    <input type="number" value="${c.min_post_gap || 5}" min="1" max="50" 
                                           onchange="updateRotation(${c.id}, null, this.value)" title="Minimum posts required">
                                </div>
                                <div class="setting-row">
                                    <span>Max Items</span>
                                    <input type="number" value="${c.max_items}" min="3" max="20" 
                                           onchange="updateMaxItems(${c.id}, this.value)">
                                </div>
                            </div>
                            <div class="carousel-actions">
                                <button class="btn" style="background: #9f7aea; color: white;" onclick="openStyleModal(${c.id})">Style Title</button>
                                ${c.carousel_type === 'custom' ? `<button class="btn btn-primary" onclick="openItemsModal(${c.id}, '${c.title.replace(/'/g, "\\'")}')">Manage Items</button>` : ''}
                                <button class="btn btn-warning" onclick="resetRotation(${c.id})" title="Reset timing">Reset</button>
                                <button class="btn ${c.is_active ? 'btn-secondary' : 'btn-success'}" 
                                        onclick="toggleCarousel(${c.id})">
                                    ${c.is_active ? 'Disable' : 'Enable'}
                                </button>
                                <button class="btn btn-danger" onclick="deleteCarousel(${c.id})">Delete</button>
                            </div>
                        </div>
                    `).join('');
                }
                
                async function addCarousel() {
                    const type = document.getElementById('carouselType').value;
                    const title = document.getElementById('carouselTitle').value.trim();
                    const position = parseInt(document.getElementById('carouselPosition').value);
                    const hours = parseInt(document.getElementById('carouselHours')?.value || 24);
                    const minPosts = parseInt(document.getElementById('carouselMinPosts')?.value || 5);
                    
                    if (!title) {
                        alert('Please enter a title');
                        return;
                    }
                    
                    try {
                        const response = await fetch('api/feed-carousels.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ 
                                action: 'add', 
                                carousel_type: type, 
                                title, 
                                position_after: position,
                                rotation_interval_hours: hours,
                                min_post_gap: minPosts
                            })
                        });
                        const data = await response.json();
                        if (data.success) {
                            document.getElementById('carouselTitle').value = '';
                            loadCarousels();
                        } else {
                            alert(data.error || 'Failed to add carousel');
                        }
                    } catch (err) {
                        alert('Failed to add carousel');
                    }
                }
                
                async function updatePosition(id, position) {
                    try {
                        await fetch('api/feed-carousels.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'update_position', id, position_after: parseInt(position) })
                        });
                    } catch (err) {
                        console.error('Failed to update position:', err);
                    }
                }
                
                async function updateMaxItems(id, maxItems) {
                    try {
                        await fetch('api/feed-carousels.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'update_max_items', id, max_items: parseInt(maxItems) })
                        });
                    } catch (err) {
                        console.error('Failed to update max items:', err);
                    }
                }
                
                async function updateRotation(id, hours, minPosts) {
                    const carousel = carousels.find(c => c.id == id);
                    if (!carousel) return;
                    
                    const newHours = hours !== null ? parseInt(hours) : carousel.rotation_interval_hours;
                    const newMinPosts = minPosts !== null ? parseInt(minPosts) : carousel.min_post_gap;
                    
                    try {
                        await fetch('api/feed-carousels.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ 
                                action: 'update_rotation', 
                                id, 
                                rotation_interval_hours: newHours,
                                min_post_gap: newMinPosts
                            })
                        });
                        loadCarousels();
                    } catch (err) {
                        console.error('Failed to update rotation:', err);
                    }
                }
                
                async function resetRotation(id) {
                    if (!confirm('Reset rotation timing? This carousel will be eligible to show again immediately.')) return;
                    
                    try {
                        await fetch('api/feed-carousels.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'reset_rotation', id })
                        });
                        loadCarousels();
                    } catch (err) {
                        console.error('Failed to reset rotation:', err);
                    }
                }
                
                async function toggleCarousel(id) {
                    try {
                        const response = await fetch('api/feed-carousels.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'toggle', id })
                        });
                        const data = await response.json();
                        if (data.success) {
                            loadCarousels();
                        }
                    } catch (err) {
                        alert('Failed to toggle carousel');
                    }
                }
                
                async function deleteCarousel(id) {
                    if (!confirm('Delete this carousel?')) return;
                    
                    try {
                        const response = await fetch('api/feed-carousels.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'delete', id })
                        });
                        const data = await response.json();
                        if (data.success) {
                            loadCarousels();
                        } else {
                            alert(data.error || 'Failed to delete');
                        }
                    } catch (err) {
                        alert('Failed to delete carousel');
                    }
                }
                
                // Title style modal management
                let styleCarouselId = null;
                
                function openStyleModal(id) {
                    const carousel = carousels.find(c => c.id == id);
                    if (!carousel) return;
                    
                    styleCarouselId = id;
                    document.getElementById('styleTitle').value = carousel.title || '';
                    document.getElementById('styleFont').value = carousel.title_font || 'inherit';
                    document.getElementById('styleFontSize').value = carousel.title_font_size || '17px';
                    document.getElementById('styleColor').value = carousel.title_color || '#050505';
                    document.getElementById('styleBgColor').value = carousel.title_bg_color || 'transparent';
                    document.getElementById('styleFontWeight').value = carousel.title_font_weight || '600';
                    document.getElementById('styleFontStyle').value = carousel.title_font_style || 'normal';
                    updateStylePreview();
                    document.getElementById('titleStyleModal').style.display = 'flex';
                }
                
                function closeStyleModal() {
                    document.getElementById('titleStyleModal').style.display = 'none';
                    styleCarouselId = null;
                }
                
                function updateStylePreview() {
                    const preview = document.getElementById('stylePreview');
                    const title = document.getElementById('styleTitle').value || 'Preview Title';
                    const font = document.getElementById('styleFont').value;
                    const fontSize = document.getElementById('styleFontSize').value;
                    const color = document.getElementById('styleColor').value;
                    const bgColor = document.getElementById('styleBgColor').value;
                    const fontWeight = document.getElementById('styleFontWeight').value;
                    const fontStyle = document.getElementById('styleFontStyle').value;
                    
                    preview.textContent = title;
                    preview.style.fontFamily = font;
                    preview.style.fontSize = fontSize;
                    preview.style.color = color;
                    preview.style.backgroundColor = bgColor;
                    preview.style.fontWeight = fontWeight;
                    preview.style.fontStyle = fontStyle;
                    preview.style.padding = bgColor !== 'transparent' ? '4px 12px' : '0';
                    preview.style.borderRadius = bgColor !== 'transparent' ? '4px' : '0';
                }
                
                async function saveTitleStyle() {
                    if (!styleCarouselId) return;
                    
                    try {
                        const response = await fetch('api/feed-carousels.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                action: 'update_title_style',
                                id: styleCarouselId,
                                title: document.getElementById('styleTitle').value,
                                title_font: document.getElementById('styleFont').value,
                                title_font_size: document.getElementById('styleFontSize').value,
                                title_color: document.getElementById('styleColor').value,
                                title_bg_color: document.getElementById('styleBgColor').value,
                                title_font_weight: document.getElementById('styleFontWeight').value,
                                title_font_style: document.getElementById('styleFontStyle').value
                            })
                        });
                        const data = await response.json();
                        if (data.success) {
                            closeStyleModal();
                            loadCarousels();
                        } else {
                            alert(data.error || 'Failed to save style');
                        }
                    } catch (err) {
                        alert('Failed to save title style');
                    }
                }
                
                // Custom carousel items management
                let currentCarouselId = null;
                let currentCarouselTitle = '';
                let customItems = [];
                
                function openItemsModal(carouselId, title) {
                    currentCarouselId = carouselId;
                    currentCarouselTitle = title;
                    document.getElementById('itemsModalTitle').textContent = 'Manage Items: ' + title;
                    document.getElementById('customItemsModal').style.display = 'flex';
                    loadCustomItems();
                }
                
                function closeItemsModal() {
                    document.getElementById('customItemsModal').style.display = 'none';
                    currentCarouselId = null;
                    resetItemForm();
                }
                
                function resetItemForm() {
                    document.getElementById('itemId').value = '';
                    document.getElementById('itemTitle').value = '';
                    document.getElementById('itemSubtitle').value = '';
                    document.getElementById('itemLink').value = '';
                    document.getElementById('itemImage').value = '';
                    document.getElementById('itemFormTitle').textContent = 'Add New Item';
                    document.getElementById('cancelEditBtn').style.display = 'none';
                }
                
                async function loadCustomItems() {
                    try {
                        const response = await fetch('api/carousel-items.php?carousel_id=' + currentCarouselId);
                        const data = await response.json();
                        if (data.success) {
                            customItems = data.items;
                            renderCustomItems();
                        }
                    } catch (err) {
                        console.error('Failed to load items:', err);
                    }
                }
                
                function renderCustomItems() {
                    const container = document.getElementById('customItemsList');
                    if (customItems.length === 0) {
                        container.innerHTML = '<p style="text-align: center; color: #65676b; padding: 20px;">No items yet. Add one above!</p>';
                        return;
                    }
                    
                    container.innerHTML = customItems.map(item => `
                        <div class="custom-item-card ${item.is_active ? '' : 'disabled'}">
                            <div class="custom-item-image">
                                ${item.image_url ? `<img src="${item.image_url}" alt="${item.title}">` : '<span>No Image</span>'}
                            </div>
                            <div class="custom-item-info">
                                <h4>${item.title}</h4>
                                ${item.subtitle ? `<p>${item.subtitle}</p>` : ''}
                                ${item.link_url ? `<small>${item.link_url.substring(0, 40)}${item.link_url.length > 40 ? '...' : ''}</small>` : ''}
                            </div>
                            <div class="custom-item-actions">
                                <button class="btn btn-secondary" onclick="editItem(${item.id})">Edit</button>
                                <button class="btn ${item.is_active ? 'btn-warning' : 'btn-success'}" onclick="toggleItem(${item.id})">${item.is_active ? 'Hide' : 'Show'}</button>
                                <button class="btn btn-danger" onclick="deleteItem(${item.id})">Delete</button>
                            </div>
                        </div>
                    `).join('');
                }
                
                async function saveItem(e) {
                    e.preventDefault();
                    const formData = new FormData();
                    const itemId = document.getElementById('itemId').value;
                    
                    formData.append('action', itemId ? 'update' : 'add');
                    formData.append('carousel_id', currentCarouselId);
                    if (itemId) formData.append('item_id', itemId);
                    formData.append('title', document.getElementById('itemTitle').value);
                    formData.append('subtitle', document.getElementById('itemSubtitle').value);
                    formData.append('link_url', document.getElementById('itemLink').value);
                    formData.append('link_type', 'url');
                    
                    const imageFile = document.getElementById('itemImage').files[0];
                    if (imageFile) {
                        formData.append('image', imageFile);
                    }
                    
                    try {
                        const response = await fetch('api/carousel-items.php', {
                            method: 'POST',
                            body: formData
                        });
                        const data = await response.json();
                        if (data.success) {
                            resetItemForm();
                            loadCustomItems();
                        } else {
                            alert(data.error || 'Failed to save item');
                        }
                    } catch (err) {
                        alert('Failed to save item');
                    }
                }
                
                function editItem(itemId) {
                    const item = customItems.find(i => i.id == itemId);
                    if (!item) return;
                    
                    document.getElementById('itemId').value = item.id;
                    document.getElementById('itemTitle').value = item.title || '';
                    document.getElementById('itemSubtitle').value = item.subtitle || '';
                    document.getElementById('itemLink').value = item.link_url || '';
                    document.getElementById('itemFormTitle').textContent = 'Edit Item';
                    document.getElementById('cancelEditBtn').style.display = 'inline-block';
                }
                
                async function toggleItem(itemId) {
                    try {
                        await fetch('api/carousel-items.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'toggle', id: itemId })
                        });
                        loadCustomItems();
                    } catch (err) {
                        alert('Failed to toggle item');
                    }
                }
                
                async function deleteItem(itemId) {
                    if (!confirm('Delete this item?')) return;
                    try {
                        await fetch('api/carousel-items.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'delete', id: itemId })
                        });
                        loadCustomItems();
                    } catch (err) {
                        alert('Failed to delete item');
                    }
                }
                
                // Load on page load
                document.addEventListener('DOMContentLoaded', loadCarousels);
                </script>
                
                <!-- Title Style Modal -->
                <div id="titleStyleModal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center;">
                    <div style="background: white; border-radius: 12px; max-width: 550px; width: 95%; padding: 24px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                            <h3 style="margin: 0;">Style Carousel Title</h3>
                            <button onclick="closeStyleModal()" style="background: none; border: none; font-size: 24px; cursor: pointer; color: #65676b;">&times;</button>
                        </div>
                        
                        <div style="background: #f0f2f5; padding: 20px; border-radius: 8px; margin-bottom: 20px; text-align: center;">
                            <span style="font-size: 12px; color: #65676b; display: block; margin-bottom: 8px;">Preview</span>
                            <h3 id="stylePreview" style="margin: 0; transition: all 0.2s;">Preview Title</h3>
                        </div>
                        
                        <div class="form-group">
                            <label for="styleTitle">Title Text</label>
                            <input type="text" id="styleTitle" oninput="updateStylePreview()" placeholder="Carousel title">
                        </div>
                        
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                            <div class="form-group">
                                <label for="styleFont">Font Family</label>
                                <select id="styleFont" onchange="updateStylePreview()">
                                    <option value="inherit">Default (System)</option>
                                    <option value="Arial, sans-serif">Arial</option>
                                    <option value="Georgia, serif">Georgia</option>
                                    <option value="'Times New Roman', serif">Times New Roman</option>
                                    <option value="'Courier New', monospace">Courier New</option>
                                    <option value="Verdana, sans-serif">Verdana</option>
                                    <option value="'Trebuchet MS', sans-serif">Trebuchet MS</option>
                                    <option value="Impact, sans-serif">Impact</option>
                                    <option value="'Comic Sans MS', cursive">Comic Sans</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="styleFontSize">Font Size</label>
                                <select id="styleFontSize" onchange="updateStylePreview()">
                                    <option value="14px">14px (Small)</option>
                                    <option value="16px">16px</option>
                                    <option value="17px" selected>17px (Default)</option>
                                    <option value="18px">18px</option>
                                    <option value="20px">20px</option>
                                    <option value="22px">22px</option>
                                    <option value="24px">24px (Large)</option>
                                    <option value="28px">28px</option>
                                    <option value="32px">32px (Extra Large)</option>
                                </select>
                            </div>
                        </div>
                        
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                            <div class="form-group">
                                <label for="styleColor">Text Color</label>
                                <div style="display: flex; gap: 8px; align-items: center;">
                                    <input type="color" id="styleColorPicker" value="#050505" onchange="document.getElementById('styleColor').value = this.value; updateStylePreview();" style="width: 40px; height: 38px; border: 1px solid #ddd; border-radius: 4px; cursor: pointer;">
                                    <input type="text" id="styleColor" value="#050505" oninput="document.getElementById('styleColorPicker').value = this.value; updateStylePreview();" style="flex: 1;">
                                </div>
                            </div>
                            <div class="form-group">
                                <label for="styleBgColor">Background Color</label>
                                <div style="display: flex; gap: 8px; align-items: center;">
                                    <input type="color" id="styleBgColorPicker" value="#ffffff" onchange="document.getElementById('styleBgColor').value = this.value; updateStylePreview();" style="width: 40px; height: 38px; border: 1px solid #ddd; border-radius: 4px; cursor: pointer;">
                                    <input type="text" id="styleBgColor" value="transparent" oninput="if(this.value !== 'transparent') document.getElementById('styleBgColorPicker').value = this.value; updateStylePreview();" style="flex: 1;" placeholder="transparent or #hex">
                                </div>
                            </div>
                        </div>
                        
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                            <div class="form-group">
                                <label for="styleFontWeight">Font Weight</label>
                                <select id="styleFontWeight" onchange="updateStylePreview()">
                                    <option value="400">Normal (400)</option>
                                    <option value="500">Medium (500)</option>
                                    <option value="600" selected>Semi-Bold (600)</option>
                                    <option value="700">Bold (700)</option>
                                    <option value="800">Extra Bold (800)</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="styleFontStyle">Font Style</label>
                                <select id="styleFontStyle" onchange="updateStylePreview()">
                                    <option value="normal" selected>Normal</option>
                                    <option value="italic">Italic</option>
                                </select>
                            </div>
                        </div>
                        
                        <div style="display: flex; gap: 10px; justify-content: flex-end; margin-top: 20px;">
                            <button type="button" class="btn btn-secondary" onclick="closeStyleModal()">Cancel</button>
                            <button type="button" class="btn btn-primary" onclick="saveTitleStyle()">Save Style</button>
                        </div>
                    </div>
                </div>
                
                <!-- Custom Items Modal -->
                <div id="customItemsModal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center;">
                    <div style="background: white; border-radius: 12px; max-width: 800px; width: 95%; max-height: 90vh; overflow-y: auto; padding: 24px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                            <h3 id="itemsModalTitle" style="margin: 0;">Manage Items</h3>
                            <button onclick="closeItemsModal()" style="background: none; border: none; font-size: 24px; cursor: pointer; color: #65676b;">&times;</button>
                        </div>
                        
                        <form onsubmit="saveItem(event)" style="background: #f0f2f5; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                            <h4 id="itemFormTitle" style="margin: 0 0 15px 0;">Add New Item</h4>
                            <input type="hidden" id="itemId">
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                                <div class="form-group" style="margin-bottom: 0;">
                                    <label>Title *</label>
                                    <input type="text" id="itemTitle" required placeholder="Item title">
                                </div>
                                <div class="form-group" style="margin-bottom: 0;">
                                    <label>Subtitle</label>
                                    <input type="text" id="itemSubtitle" placeholder="Optional subtitle">
                                </div>
                                <div class="form-group" style="margin-bottom: 0;">
                                    <label>Link URL</label>
                                    <input type="url" id="itemLink" placeholder="https://...">
                                </div>
                                <div class="form-group" style="margin-bottom: 0;">
                                    <label>Image</label>
                                    <input type="file" id="itemImage" accept="image/*">
                                </div>
                            </div>
                            <div style="margin-top: 15px; display: flex; gap: 10px;">
                                <button type="submit" class="btn btn-primary">Save Item</button>
                                <button type="button" id="cancelEditBtn" class="btn btn-secondary" style="display: none;" onclick="resetItemForm()">Cancel Edit</button>
                            </div>
                        </form>
                        
                        <h4 style="margin: 0 0 15px 0;">Carousel Items</h4>
                        <div id="customItemsList">
                            <p style="text-align: center; color: #65676b;">Loading...</p>
                        </div>
                    </div>
                </div>
                
                <style>
                    .custom-item-card {
                        background: white;
                        border: 1px solid #e4e6e9;
                        border-radius: 8px;
                        padding: 12px;
                        margin-bottom: 10px;
                        display: flex;
                        align-items: center;
                        gap: 15px;
                    }
                    .custom-item-card.disabled {
                        opacity: 0.6;
                        background: #f9f9f9;
                    }
                    .custom-item-image {
                        width: 60px;
                        height: 60px;
                        border-radius: 8px;
                        background: #f0f2f5;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        overflow: hidden;
                        flex-shrink: 0;
                    }
                    .custom-item-image img {
                        width: 100%;
                        height: 100%;
                        object-fit: cover;
                    }
                    .custom-item-image span {
                        font-size: 11px;
                        color: #65676b;
                    }
                    .custom-item-info {
                        flex: 1;
                    }
                    .custom-item-info h4 {
                        margin: 0 0 4px 0;
                        font-size: 14px;
                    }
                    .custom-item-info p {
                        margin: 0;
                        color: #65676b;
                        font-size: 13px;
                    }
                    .custom-item-info small {
                        color: #1877f2;
                        font-size: 11px;
                    }
                    .custom-item-actions {
                        display: flex;
                        gap: 6px;
                    }
                    .custom-item-actions .btn {
                        padding: 6px 12px;
                        font-size: 12px;
                    }
                    .btn-warning {
                        background: #ed8936;
                        color: white;
                    }
                    .btn-warning:hover {
                        background: #dd6b20;
                    }
                </style>

            <?php elseif ($activeTab === 'shorts'): ?>
                <h2>YouTube Shorts</h2>
                <p style="color: #65676b; margin-bottom: 20px;">Manage YouTube Shorts carousels that appear in the community feed.</p>
                
                <h3>Active YouTube Shorts Carousels</h3>
                <div id="shortsCarouselsList" style="min-height: 100px;">
                    <p style="text-align: center; color: #65676b; padding: 20px;">Loading...</p>
                </div>
                
                <div style="background: white; border: 1px solid #e4e6e9; border-radius: 12px; padding: 24px; max-width: 900px; margin-top: 30px;">
                    <h3 style="margin: 0 0 15px 0;">Scrape New YouTube Shorts</h3>
                    <div class="form-group">
                        <label style="font-weight: 600; margin-bottom: 10px; display: block;">Carousel Title</label>
                        <input type="text" id="shortsCarouselTitle" placeholder="e.g., Trending Shorts" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px;">
                    </div>
                    
                    <div style="display: flex; gap: 15px; margin-top: 15px; flex-wrap: wrap;">
                        <div class="form-group" style="margin-bottom: 0;">
                            <label style="font-weight: 600; margin-bottom: 10px; display: block;">Position</label>
                            <input type="number" id="shortsPosition" value="2" min="1" max="50" style="width: 80px; padding: 10px; border: 1px solid #ddd; border-radius: 6px;">
                        </div>
                        <div class="form-group" style="margin-bottom: 0;">
                            <label style="font-weight: 600; margin-bottom: 10px; display: block;">Hours Between</label>
                            <input type="number" id="shortsHours" value="24" min="0" max="168" style="width: 80px; padding: 10px; border: 1px solid #ddd; border-radius: 6px;">
                        </div>
                        <div class="form-group" style="margin-bottom: 0;">
                            <label style="font-weight: 600; margin-bottom: 10px; display: block;">Min Posts</label>
                            <input type="number" id="shortsMinPosts" value="5" min="0" max="50" style="width: 80px; padding: 10px; border: 1px solid #ddd; border-radius: 6px;">
                        </div>
                        <div class="form-group" style="margin-bottom: 0;">
                            <label style="font-weight: 600; margin-bottom: 10px; display: block;">Per Subject</label>
                            <input type="number" id="shortsPerSubject" value="2" min="1" max="10" style="width: 80px; padding: 10px; border: 1px solid #ddd; border-radius: 6px;">
                        </div>
                    </div>
                    
                    <div class="form-group" style="margin-top: 15px;">
                        <label style="font-weight: 600; margin-bottom: 10px; display: block;">Subjects (one per line)</label>
                        <textarea id="shortsSubjects" rows="4" placeholder="politics news&#10;debate&#10;trending" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; font-family: inherit;"></textarea>
                    </div>
                    
                    <div style="margin-top: 20px; display: flex; gap: 12px; align-items: center;">
                        <button type="button" onclick="runShortsScraper()" id="scrapeBtn" style="background: linear-gradient(135deg, #e41e3f, #c41e3f); color: white; border: none; padding: 12px 24px; border-radius: 8px; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 8px;">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M19.615 3.184c-3.604-.246-11.631-.245-15.23 0-3.897.266-4.356 2.62-4.385 8.816.029 6.185.484 8.549 4.385 8.816 3.6.245 11.626.246 15.23 0 3.897-.266 4.356-2.62 4.385-8.816-.029-6.185-.484-8.549-4.385-8.816zm-10.615 12.816v-8l8 3.993-8 4.007z"/></svg>
                            Scrape Shorts
                        </button>
                        <button type="button" onclick="testScraper()" style="background: #f0f2f5; color: #333; border: none; padding: 12px 24px; border-radius: 8px; font-weight: 500; cursor: pointer;">
                            Test Setup
                        </button>
                    </div>
                    
                    <div id="scrapeProgress" style="display: none; margin-top: 20px; padding: 15px; background: #e3f2fd; border-radius: 8px;">
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <div class="spinner" style="width: 20px; height: 20px; border: 3px solid #1877f2; border-top-color: transparent; border-radius: 50%; animation: spin 1s linear infinite;"></div>
                            <span id="scrapeStatus">Scraping YouTube Shorts... This may take a minute.</span>
                        </div>
                    </div>
                    
                    <div id="scrapeResult" style="display: none; margin-top: 20px;"></div>
                </div>
                
                <div style="background: white; border: 1px solid #e4e6e9; border-radius: 12px; padding: 24px; max-width: 700px; margin-top: 24px;">
                    <h3 style="margin: 0 0 15px 0; display: flex; align-items: center; gap: 10px;">
                        <span style="color: #ff0000;">🔄</span> Auto-Post Cron Job
                    </h3>
                    
                    <div style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 15px; margin-bottom: 20px;">
                        <strong style="color: #856404;">💡 Cost Saving Tip</strong>
                        <p style="margin: 8px 0 0 0; font-size: 13px; color: #856404;">
                            Disabling here stops new posts but Replit still charges for scheduled runs. 
                            To stop all charges, click <strong>Publish → find your Scheduled Deployment → Shut Down</strong>.
                        </p>
                        <details style="margin-top: 10px;">
                            <summary style="cursor: pointer; font-size: 13px; color: #856404; font-weight: 600;">How to set up or change the schedule</summary>
                            <ol style="margin: 10px 0 0 15px; font-size: 13px; color: #664d03; line-height: 1.6;">
                                <li>Click the <strong>Publish</strong> button in the top-right of Replit (or search "Deployments" in the command bar)</li>
                                <li>Click <strong>New Deployment</strong> → <strong>Scheduled</strong></li>
                                <li>Set the <strong>Schedule</strong> using natural language or a cron expression:</li>
                            </ol>
                            <table style="margin: 10px 0 10px 15px; font-size: 12px; border-collapse: collapse;">
                                <tr style="background: #ffeeba;">
                                    <th style="padding: 6px 12px; text-align: left; border: 1px solid #e0c97a;">Frequency</th>
                                    <th style="padding: 6px 12px; text-align: left; border: 1px solid #e0c97a;">Natural Language</th>
                                    <th style="padding: 6px 12px; text-align: left; border: 1px solid #e0c97a;">Cron Expression</th>
                                </tr>
                                <tr>
                                    <td style="padding: 6px 12px; border: 1px solid #e0c97a;">Every 2 hours</td>
                                    <td style="padding: 6px 12px; border: 1px solid #e0c97a;">"Every 2 hours"</td>
                                    <td style="padding: 6px 12px; border: 1px solid #e0c97a; font-family: monospace;">0 */2 * * *</td>
                                </tr>
                                <tr>
                                    <td style="padding: 6px 12px; border: 1px solid #e0c97a;">Every 12 hours</td>
                                    <td style="padding: 6px 12px; border: 1px solid #e0c97a;">"Every 12 hours"</td>
                                    <td style="padding: 6px 12px; border: 1px solid #e0c97a; font-family: monospace;">0 */12 * * *</td>
                                </tr>
                                <tr>
                                    <td style="padding: 6px 12px; border: 1px solid #e0c97a;">Every 24 hours</td>
                                    <td style="padding: 6px 12px; border: 1px solid #e0c97a;">"Once a day at midnight"</td>
                                    <td style="padding: 6px 12px; border: 1px solid #e0c97a; font-family: monospace;">0 0 * * *</td>
                                </tr>
                            </table>
                            <ol start="4" style="margin: 0 0 0 15px; font-size: 13px; color: #664d03; line-height: 1.6;">
                                <li>Set <strong>Run command</strong>: <code style="background: #ffeeba; padding: 2px 6px; border-radius: 3px;">cd politicscompletedownload && php scripts/cron_runner.php</code></li>
                                <li>Set <strong>Timeout</strong>: 5 minutes</li>
                                <li>Click <strong>Deploy</strong></li>
                            </ol>
                        </details>
                        
                        <details style="margin-top: 10px;">
                            <summary style="cursor: pointer; font-size: 13px; color: #856404; font-weight: 600;">How to fully disable the cron job</summary>
                            <ol style="margin: 10px 0 0 15px; font-size: 13px; color: #664d03; line-height: 1.6;">
                                <li>Click the <strong>Publish</strong> button in the top-right of Replit (or search "Deployments" in the command bar)</li>
                                <li>Find your <strong>Scheduled Deployment</strong> (YouTube Shorts Cron)</li>
                                <li>Click the <strong>⋮</strong> menu next to it</li>
                                <li>Select <strong>Shut Down</strong> to stop it completely (stops all billing)</li>
                                <li>Or select <strong>Pause</strong> to temporarily stop it (billing may continue)</li>
                            </ol>
                        </details>
                    </div>
                    
                    <?php
                    $cronKeywordsStmt = $pdo->query("SELECT setting_value FROM site_settings WHERE setting_key = 'youtube_shorts_keywords' LIMIT 1");
                    $cronKeywordsRow = $cronKeywordsStmt->fetch(PDO::FETCH_ASSOC);
                    $cronKeywords = $cronKeywordsRow ? json_decode($cronKeywordsRow['setting_value'], true) : ['politics', 'news', 'debate'];
                    
                    $cronPerKeywordStmt = $pdo->query("SELECT setting_value FROM site_settings WHERE setting_key = 'youtube_shorts_per_keyword' LIMIT 1");
                    $cronPerKeywordRow = $cronPerKeywordStmt->fetch(PDO::FETCH_ASSOC);
                    $cronPerKeyword = $cronPerKeywordRow ? intval($cronPerKeywordRow['setting_value']) : 1;
                    
                    $cronEnabledStmt = $pdo->query("SELECT setting_value FROM site_settings WHERE setting_key = 'youtube_shorts_cron_enabled' LIMIT 1");
                    $cronEnabledRow = $cronEnabledStmt->fetch(PDO::FETCH_ASSOC);
                    $cronEnabled = $cronEnabledRow && $cronEnabledRow['setting_value'] === 'true';
                    
                    $cronFrequencyStmt = $pdo->query("SELECT setting_value FROM site_settings WHERE setting_key = 'youtube_shorts_frequency_hours' LIMIT 1");
                    $cronFrequencyRow = $cronFrequencyStmt->fetch(PDO::FETCH_ASSOC);
                    $cronFrequency = $cronFrequencyRow ? intval($cronFrequencyRow['setting_value']) : 24;
                    
                    $cronLastRunStmt = $pdo->query("SELECT setting_value FROM site_settings WHERE setting_key = 'youtube_shorts_last_run' LIMIT 1");
                    $cronLastRunRow = $cronLastRunStmt->fetch(PDO::FETCH_ASSOC);
                    $cronLastRun = $cronLastRunRow ? $cronLastRunRow['setting_value'] : 'Never';
                    ?>
                    
                    <div style="display: flex; align-items: center; gap: 20px; margin-bottom: 20px; padding: 15px; background: <?php echo $cronEnabled ? '#d4edda' : '#f8d7da'; ?>; border-radius: 8px;">
                        <div style="flex: 1;">
                            <strong style="color: <?php echo $cronEnabled ? '#155724' : '#721c24'; ?>;">
                                <?php echo $cronEnabled ? '✓ Cron Enabled' : '✗ Cron Disabled'; ?>
                            </strong>
                            <p style="margin: 5px 0 0 0; font-size: 13px; color: #65676b;">
                                Last run: <?php echo htmlspecialchars($cronLastRun); ?>
                            </p>
                        </div>
                        <button type="button" onclick="toggleCronEnabled()" id="cronToggleBtn" 
                                style="background: <?php echo $cronEnabled ? '#dc3545' : '#28a745'; ?>; color: white; border: none; padding: 10px 20px; border-radius: 6px; font-weight: 600; cursor: pointer;">
                            <?php echo $cronEnabled ? 'Disable' : 'Enable'; ?>
                        </button>
                    </div>
                    
                    <div style="display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 15px;">
                        <div class="form-group" style="margin-bottom: 0;">
                            <label style="font-weight: 600; margin-bottom: 8px; display: block;">Frequency</label>
                            <select id="cronFrequency" style="padding: 10px; border: 1px solid #ddd; border-radius: 6px; min-width: 150px;">
                                <option value="1" <?php echo $cronFrequency == 1 ? 'selected' : ''; ?>>Every 1 hour</option>
                                <option value="2" <?php echo $cronFrequency == 2 ? 'selected' : ''; ?>>Every 2 hours</option>
                                <option value="6" <?php echo $cronFrequency == 6 ? 'selected' : ''; ?>>Every 6 hours</option>
                                <option value="12" <?php echo $cronFrequency == 12 ? 'selected' : ''; ?>>Every 12 hours</option>
                                <option value="24" <?php echo $cronFrequency == 24 ? 'selected' : ''; ?>>Every 24 hours</option>
                                <option value="48" <?php echo $cronFrequency == 48 ? 'selected' : ''; ?>>Every 2 days</option>
                                <option value="168" <?php echo $cronFrequency == 168 ? 'selected' : ''; ?>>Every week</option>
                            </select>
                        </div>
                        <div class="form-group" style="margin-bottom: 0;">
                            <label style="font-weight: 600; margin-bottom: 8px; display: block;">Shorts per Keyword</label>
                            <input type="number" id="cronPerKeyword" value="<?php echo $cronPerKeyword; ?>" min="1" max="5" style="width: 80px; padding: 10px; border: 1px solid #ddd; border-radius: 6px;">
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label style="font-weight: 600; margin-bottom: 8px; display: block;">Keywords (one per line)</label>
                        <textarea id="cronKeywords" rows="4" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; font-family: inherit;"><?php echo htmlspecialchars(implode("\n", $cronKeywords)); ?></textarea>
                    </div>
                    
                    <input type="hidden" id="cronEnabled" value="<?php echo $cronEnabled ? 'true' : 'false'; ?>">
                    
                    <div style="margin-top: 20px; display: flex; gap: 12px;">
                        <button type="button" onclick="saveCronSettings()" style="background: linear-gradient(135deg, #ff0000, #cc0000); color: white; border: none; padding: 12px 24px; border-radius: 8px; font-weight: 600; cursor: pointer;">
                            Save Settings
                        </button>
                        <button type="button" onclick="runCronNow()" style="background: #f0f2f5; color: #333; border: none; padding: 12px 24px; border-radius: 8px; font-weight: 500; cursor: pointer;">
                            Run Now
                        </button>
                    </div>
                    
                    <div id="cronResult" style="display: none; margin-top: 15px;"></div>
                </div>
                
                <style>
                @keyframes spin {
                    to { transform: rotate(360deg); }
                }
                .shorts-carousel-card {
                    background: white;
                    border: 1px solid #e4e6e9;
                    border-radius: 8px;
                    padding: 15px 20px;
                    margin-bottom: 10px;
                    display: flex;
                    align-items: center;
                    gap: 20px;
                    flex-wrap: wrap;
                }
                .shorts-carousel-card:hover {
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                }
                .shorts-carousel-card.disabled {
                    opacity: 0.6;
                    background: #f9f9f9;
                }
                .shorts-icon {
                    width: 50px;
                    height: 50px;
                    border-radius: 10px;
                    background: linear-gradient(135deg, #ff0000, #cc0000);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 24px;
                    flex-shrink: 0;
                    color: white;
                }
                .shorts-info {
                    flex: 1;
                    min-width: 150px;
                }
                .shorts-info h4 {
                    margin: 0 0 4px 0;
                    font-size: 16px;
                }
                .shorts-info p {
                    margin: 0;
                    color: #65676b;
                    font-size: 13px;
                }
                .shorts-settings {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 8px;
                }
                .shorts-setting-row {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    background: #f0f2f5;
                    padding: 6px 10px;
                    border-radius: 6px;
                    min-width: 70px;
                }
                .shorts-setting-row span {
                    font-size: 10px;
                    color: #65676b;
                    margin-bottom: 4px;
                }
                .shorts-setting-row input {
                    width: 50px;
                    padding: 4px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    text-align: center;
                    font-size: 13px;
                }
                .shorts-status {
                    font-size: 11px;
                    margin-top: 4px;
                    padding: 2px 8px;
                    border-radius: 10px;
                    display: inline-block;
                }
                .shorts-status.eligible {
                    background: #d4edda;
                    color: #155724;
                }
                .shorts-status.waiting {
                    background: #fff3cd;
                    color: #856404;
                }
                .shorts-actions {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 6px;
                }
                .shorts-actions .btn {
                    padding: 6px 12px;
                    font-size: 12px;
                }
                </style>
                
                <script>
                let shortsCarousels = [];
                
                async function loadShortsCarousels() {
                    try {
                        const response = await fetch('api/feed-carousels.php');
                        const data = await response.json();
                        if (data.success) {
                            shortsCarousels = data.carousels.filter(c => c.carousel_type === 'custom' && (c.title.toLowerCase().includes('youtube') || c.title.toLowerCase().includes('shorts')));
                            renderShortsCarousels();
                        }
                    } catch (error) {
                        console.error('Failed to load shorts carousels:', error);
                    }
                }
                
                function renderShortsCarousels() {
                    const container = document.getElementById('shortsCarouselsList');
                    
                    if (shortsCarousels.length === 0) {
                        container.innerHTML = '<p style="text-align: center; color: #65676b; padding: 40px;">No YouTube Shorts carousels yet. Scrape some shorts above or run the cron job!</p>';
                        return;
                    }
                    
                    container.innerHTML = shortsCarousels.map(c => `
                        <div class="shorts-carousel-card ${c.is_active ? '' : 'disabled'}" data-id="${c.id}">
                            <div class="shorts-icon">▶</div>
                            <div class="shorts-info">
                                <h4>${c.title}</h4>
                                <p>Custom Carousel</p>
                                <div class="shorts-status ${c.is_eligible ? 'eligible' : 'waiting'}">
                                    ${c.is_eligible ? '✓ Ready to show' : '⏳ Waiting'}
                                    ${c.posts_since_last_show !== undefined ? ` (${c.posts_since_last_show} posts since last)` : ''}
                                </div>
                            </div>
                            <div class="shorts-settings">
                                <div class="shorts-setting-row">
                                    <span>Position</span>
                                    <input type="number" value="${c.position_after}" min="0" max="50" 
                                           onchange="updateShortsPosition(${c.id}, this.value)" title="0 = top of feed">
                                </div>
                                <div class="shorts-setting-row">
                                    <span>Hours</span>
                                    <input type="number" value="${c.rotation_interval_hours || 0}" min="0" max="168" 
                                           onchange="updateShortsRotation(${c.id}, this.value, null)">
                                </div>
                                <div class="shorts-setting-row">
                                    <span>Min Posts</span>
                                    <input type="number" value="${c.min_post_gap || 0}" min="0" max="50" 
                                           onchange="updateShortsRotation(${c.id}, null, this.value)">
                                </div>
                                <div class="shorts-setting-row">
                                    <span>Max Items</span>
                                    <input type="number" value="${c.max_items}" min="3" max="20" 
                                           onchange="updateShortsMaxItems(${c.id}, this.value)">
                                </div>
                            </div>
                            <div class="shorts-actions">
                                <button class="btn" style="background: #9f7aea; color: white;" onclick="openShortsStyleModal(${c.id})">Style Title</button>
                                <button class="btn btn-primary" onclick="openShortsItemsModal(${c.id}, '${c.title.replace(/'/g, "\\'")}')">Manage Items</button>
                                <button class="btn btn-warning" onclick="resetShortsRotation(${c.id})">Reset</button>
                                <button class="btn ${c.is_active ? 'btn-secondary' : 'btn-success'}" 
                                        onclick="toggleShortsCarousel(${c.id})">
                                    ${c.is_active ? 'Disable' : 'Enable'}
                                </button>
                                <button class="btn btn-danger" onclick="deleteShortsCarousel(${c.id})">Delete</button>
                            </div>
                        </div>
                    `).join('');
                }
                
                async function updateShortsPosition(id, position) {
                    await fetch('api/feed-carousels.php', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action: 'update_position', id, position_after: parseInt(position) })
                    });
                }
                
                async function updateShortsMaxItems(id, maxItems) {
                    await fetch('api/feed-carousels.php', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action: 'update_max_items', id, max_items: parseInt(maxItems) })
                    });
                }
                
                async function updateShortsRotation(id, hours, minPosts) {
                    const carousel = shortsCarousels.find(c => c.id == id);
                    if (!carousel) return;
                    
                    const newHours = hours !== null ? parseInt(hours) : carousel.rotation_interval_hours;
                    const newMinPosts = minPosts !== null ? parseInt(minPosts) : carousel.min_post_gap;
                    
                    await fetch('api/feed-carousels.php', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ 
                            action: 'update_rotation', 
                            id, 
                            rotation_interval_hours: newHours,
                            min_post_gap: newMinPosts
                        })
                    });
                    loadShortsCarousels();
                }
                
                async function resetShortsRotation(id) {
                    if (!confirm('Reset rotation timing? This carousel will be eligible to show again immediately.')) return;
                    await fetch('api/feed-carousels.php', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action: 'reset_rotation', id })
                    });
                    loadShortsCarousels();
                }
                
                async function toggleShortsCarousel(id) {
                    await fetch('api/feed-carousels.php', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action: 'toggle', id })
                    });
                    loadShortsCarousels();
                }
                
                async function deleteShortsCarousel(id) {
                    if (!confirm('Delete this YouTube Shorts carousel?')) return;
                    await fetch('api/feed-carousels.php', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action: 'delete', id })
                    });
                    loadShortsCarousels();
                }
                
                function openShortsStyleModal(id) {
                    window.location.href = '?tab=carousels&style=' + id;
                }
                
                function openShortsItemsModal(id, title) {
                    window.location.href = '?tab=carousels&items=' + id;
                }
                
                document.addEventListener('DOMContentLoaded', loadShortsCarousels);
                
                async function toggleCronEnabled() {
                    const currentEnabled = document.getElementById('cronEnabled').value === 'true';
                    const newEnabled = !currentEnabled;
                    
                    try {
                        const formData = new FormData();
                        formData.append('action', 'toggle_cron');
                        formData.append('enabled', newEnabled ? 'true' : 'false');
                        
                        const response = await fetch('api/shorts-scraper.php', {
                            method: 'POST',
                            body: formData
                        });
                        
                        const data = await response.json();
                        if (data.success) {
                            location.reload();
                        } else {
                            alert('Failed to toggle: ' + (data.error || 'Unknown error'));
                        }
                    } catch (err) {
                        alert('Error: ' + err.message);
                    }
                }
                
                async function saveCronSettings() {
                    const keywords = document.getElementById('cronKeywords').value.trim().split('\n').filter(k => k.trim());
                    const perKeyword = document.getElementById('cronPerKeyword').value;
                    const frequency = document.getElementById('cronFrequency').value;
                    const enabled = document.getElementById('cronEnabled').value;
                    
                    if (keywords.length === 0) {
                        alert('Please enter at least one keyword');
                        return;
                    }
                    
                    try {
                        const formData = new FormData();
                        formData.append('action', 'save_cron_settings');
                        formData.append('keywords', JSON.stringify(keywords));
                        formData.append('per_keyword', perKeyword);
                        formData.append('frequency', frequency);
                        formData.append('enabled', enabled);
                        
                        const response = await fetch('api/shorts-scraper.php', {
                            method: 'POST',
                            body: formData
                        });
                        
                        const data = await response.json();
                        const resultDiv = document.getElementById('cronResult');
                        resultDiv.style.display = 'block';
                        
                        if (data.success) {
                            resultDiv.innerHTML = '<div style="padding: 12px; background: #d4edda; border-radius: 8px; color: #155724;">Settings saved successfully!</div>';
                        } else {
                            resultDiv.innerHTML = '<div style="padding: 12px; background: #f8d7da; border-radius: 8px; color: #721c24;">Error: ' + (data.error || 'Unknown error') + '</div>';
                        }
                    } catch (err) {
                        alert('Error saving settings: ' + err.message);
                    }
                }
                
                async function runCronNow() {
                    if (!confirm('This will scrape YouTube Shorts and post them to the feed now. Continue?')) return;
                    
                    const resultDiv = document.getElementById('cronResult');
                    resultDiv.style.display = 'block';
                    resultDiv.innerHTML = '<div style="padding: 12px; background: #e3f2fd; border-radius: 8px; display: flex; align-items: center; gap: 10px;"><div class="spinner" style="width: 16px; height: 16px; border: 2px solid #1877f2; border-top-color: transparent; border-radius: 50%; animation: spin 1s linear infinite;"></div> Running cron job...</div>';
                    
                    try {
                        const formData = new FormData();
                        formData.append('action', 'run_cron');
                        
                        const response = await fetch('api/shorts-scraper.php', {
                            method: 'POST',
                            body: formData
                        });
                        
                        const data = await response.json();
                        
                        if (data.success) {
                            resultDiv.innerHTML = '<div style="padding: 12px; background: #d4edda; border-radius: 8px; color: #155724;">Posted ' + data.posted + ' YouTube Shorts to the feed!</div>';
                        } else {
                            resultDiv.innerHTML = '<div style="padding: 12px; background: #f8d7da; border-radius: 8px; color: #721c24;">Error: ' + (data.error || 'Unknown error') + '</div>';
                        }
                    } catch (err) {
                        resultDiv.innerHTML = '<div style="padding: 12px; background: #f8d7da; border-radius: 8px; color: #721c24;">Error: ' + err.message + '</div>';
                    }
                }
                
                async function testScraper() {
                    try {
                        const response = await fetch('api/shorts-scraper.php?action=test');
                        const data = await response.json();
                        alert('Python: ' + data.python_version + '\nyt-dlp: ' + (data.ytdlp_version || 'Not found'));
                    } catch (err) {
                        alert('Test failed: ' + err.message);
                    }
                }
                
                async function runShortsScraper() {
                    const title = document.getElementById('shortsCarouselTitle').value.trim();
                    const position = document.getElementById('shortsPosition').value;
                    const hours = document.getElementById('shortsHours').value;
                    const minPosts = document.getElementById('shortsMinPosts').value;
                    const subjectsText = document.getElementById('shortsSubjects').value.trim();
                    const perSubject = document.getElementById('shortsPerSubject').value;
                    
                    if (!title) {
                        alert('Please enter a carousel title');
                        return;
                    }
                    
                    if (!subjectsText) {
                        alert('Please enter at least one subject');
                        return;
                    }
                    
                    const subjects = subjectsText.split('\n').map(s => s.trim()).filter(s => s);
                    
                    if (subjects.length === 0) {
                        alert('Please enter at least one valid subject');
                        return;
                    }
                    
                    const btn = document.getElementById('scrapeBtn');
                    btn.disabled = true;
                    btn.style.opacity = '0.6';
                    
                    document.getElementById('scrapeProgress').style.display = 'block';
                    document.getElementById('scrapeResult').style.display = 'none';
                    
                    try {
                        const formData = new FormData();
                        formData.append('action', 'scrape');
                        formData.append('carousel_title', title);
                        formData.append('position', position);
                        formData.append('hours', hours);
                        formData.append('min_posts', minPosts);
                        formData.append('per_subject', perSubject);
                        subjects.forEach(s => formData.append('subjects[]', s));
                        
                        const response = await fetch('api/shorts-scraper.php', {
                            method: 'POST',
                            body: formData
                        });
                        
                        const data = await response.json();
                        
                        document.getElementById('scrapeProgress').style.display = 'none';
                        
                        if (data.success) {
                            const resultDiv = document.getElementById('scrapeResult');
                            resultDiv.style.display = 'block';
                            resultDiv.innerHTML = `
                                <div style="padding: 15px; background: #d4edda; border-radius: 8px; color: #155724;">
                                    <strong>Success!</strong> Created carousel "${title}" with ${data.shorts_count} shorts.
                                    <br><br>
                                    <a href="?tab=carousels" style="color: #155724; font-weight: 600;">View in Feed Carousels</a>
                                </div>
                                <div style="margin-top: 15px; max-height: 300px; overflow-y: auto;">
                                    <strong>Scraped Shorts:</strong>
                                    <ul style="margin-top: 10px; padding-left: 20px;">
                                        ${data.shorts.map(s => `<li style="margin-bottom: 8px;"><a href="${s.url}" target="_blank">${s.title}</a></li>`).join('')}
                                    </ul>
                                </div>
                            `;
                            
                            document.getElementById('shortsCarouselTitle').value = '';
                            document.getElementById('shortsSubjects').value = '';
                            loadShortsCarousels();
                        } else {
                            const resultDiv = document.getElementById('scrapeResult');
                            resultDiv.style.display = 'block';
                            resultDiv.innerHTML = `
                                <div style="padding: 15px; background: #f8d7da; border-radius: 8px; color: #721c24;">
                                    <strong>Error:</strong> ${data.error || 'Unknown error'}
                                    ${data.debug ? '<br><br><pre style="font-size: 11px; overflow: auto;">' + data.debug + '</pre>' : ''}
                                </div>
                            `;
                        }
                    } catch (err) {
                        document.getElementById('scrapeProgress').style.display = 'none';
                        const resultDiv = document.getElementById('scrapeResult');
                        resultDiv.style.display = 'block';
                        resultDiv.innerHTML = `
                            <div style="padding: 15px; background: #f8d7da; border-radius: 8px; color: #721c24;">
                                <strong>Error:</strong> ${err.message}
                            </div>
                        `;
                    } finally {
                        btn.disabled = false;
                        btn.style.opacity = '1';
                    }
                }
                </script>

            <?php elseif ($activeTab === 'contests'): ?>
                <?php
                // Get all contests
                $contestsStmt = $pdo->query("SELECT * FROM contests ORDER BY created_at DESC");
                $contests = $contestsStmt->fetchAll();
                ?>
                
                <h2>Contest Management</h2>
                <p style="color: #65676b; margin-bottom: 20px;">Create and manage contests with formatted text and images.</p>
                
                <?php if (isset($_GET['contest_added'])): ?>
                    <div class="alert alert-success">Contest created successfully!</div>
                <?php endif; ?>
                <?php if (isset($_GET['contest_updated'])): ?>
                    <div class="alert alert-success">Contest updated successfully!</div>
                <?php endif; ?>
                <?php if (isset($_GET['contest_deleted'])): ?>
                    <div class="alert alert-success">Contest deleted successfully!</div>
                <?php endif; ?>
                <?php if (isset($_GET['error']) && $_GET['error'] === 'title_required'): ?>
                    <div class="alert" style="background: #ffe5e5; color: #e41e3f;">Title is required.</div>
                <?php endif; ?>
                
                <!-- Add New Contest Form -->
                <div style="background: white; border: 1px solid #e4e6e9; border-radius: 12px; padding: 24px; margin-bottom: 30px;">
                    <h3 style="margin: 0 0 20px 0; font-size: 18px;">Create New Contest</h3>
                    <form method="POST" enctype="multipart/form-data" onsubmit="return prepareContestSubmit(this, 'add')">
                        <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                        <input type="hidden" name="action" value="add_contest">
                        <input type="hidden" name="content" id="addContestContent">
                        
                        <div class="form-group" style="margin-bottom: 15px;">
                            <label style="font-weight: 600; margin-bottom: 8px; display: block;">Contest Title *</label>
                            <input type="text" name="title" required style="width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 16px;" placeholder="Enter contest title">
                        </div>
                        
                        <div class="form-group" style="margin-bottom: 15px;">
                            <label style="font-weight: 600; margin-bottom: 8px; display: block;">Contest Details</label>
                            <div id="addContestEditor" style="height: 250px; background: white; border: 1px solid #ddd; border-radius: 8px;"></div>
                        </div>
                        
                        <div class="form-group" style="margin-bottom: 20px;">
                            <label style="font-weight: 600; margin-bottom: 8px; display: block;">Contest Image (for feed post)</label>
                            <input type="file" name="image" accept="image/*" style="padding: 8px 0;">
                            <small style="display: block; color: #65676b; margin-top: 5px;">Recommended: 1200x630 pixels (JPG, PNG, GIF, WebP)</small>
                        </div>
                        
                        <div class="form-group" style="margin-bottom: 20px;">
                            <label style="font-weight: 600; margin-bottom: 8px; display: block;">Expiration Date</label>
                            <input type="datetime-local" name="expires_at" style="width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 14px;">
                            <small style="display: block; color: #65676b; margin-top: 5px;">Leave empty for no expiration. Contest will be hidden after this date.</small>
                        </div>
                        
                        <div style="background: #f8f9fa; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
                            <h4 style="margin: 0 0 15px 0; font-size: 16px;">Display Options</h4>
                            
                            <div class="form-group" style="margin-bottom: 15px;">
                                <label style="font-weight: 600; margin-bottom: 8px; display: block;">Display Location</label>
                                <select name="display_location" id="addDisplayLocation" onchange="toggleDisplayOptions('add')" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px;">
                                    <option value="none">None (Save only)</option>
                                    <option value="feed">Show in Feed</option>
                                    <option value="header">Show in Header</option>
                                    <option value="both">Both Feed and Header</option>
                                </select>
                            </div>
                            
                            <div id="addHeaderOptions" style="display: none; margin-top: 15px; padding: 15px; background: white; border-radius: 6px; border: 1px solid #ddd;">
                                <h5 style="margin: 0 0 12px 0; color: #333;">Header Icon Settings</h5>
                                
                                <div class="form-group" style="margin-bottom: 12px;">
                                    <label style="font-weight: 500; margin-bottom: 6px; display: block;">Header Icon</label>
                                    <input type="file" name="icon" accept="image/*" style="padding: 6px 0;">
                                    <small style="color: #65676b; font-size: 12px;">44x44 pixels recommended (PNG with transparency preferred)</small>
                                </div>
                                
                                <div class="form-group" style="margin-bottom: 12px;">
                                    <label style="font-weight: 500; margin-bottom: 6px; display: block;">Header Title (shown below icon)</label>
                                    <input type="text" name="header_title" placeholder="e.g., Contest" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                                </div>
                                
                                <div style="display: flex; gap: 15px;">
                                    <div class="form-group" style="flex: 1;">
                                        <label style="font-weight: 500; margin-bottom: 6px; display: block;">Title Color</label>
                                        <input type="color" name="header_title_color" value="#00ffff" style="width: 60px; height: 35px; border: 1px solid #ddd; border-radius: 4px; cursor: pointer;">
                                    </div>
                                    <div class="form-group" style="flex: 1;">
                                        <label style="font-weight: 500; margin-bottom: 6px; display: block;">Title Size</label>
                                        <select name="header_title_size" style="padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                                            <option value="10px">Small (10px)</option>
                                            <option value="12px" selected>Medium (12px)</option>
                                            <option value="14px">Large (14px)</option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <button type="submit" class="btn btn-primary" style="padding: 12px 24px; font-size: 16px;">Create Contest</button>
                    </form>
                </div>
                
                <!-- Existing Contests -->
                <h3 style="margin: 0 0 15px 0;">Existing Contests (<?php echo count($contests); ?>)</h3>
                
                <?php if (empty($contests)): ?>
                    <p style="color: #65676b; padding: 40px; text-align: center; background: #f8f9fa; border-radius: 12px;">No contests created yet.</p>
                <?php else: ?>
                    <div style="display: grid; gap: 20px;">
                        <?php foreach ($contests as $contest): ?>
                            <?php 
                            $contestImageUrl = '';
                            if ($contest['image_url']) {
                                $contestImageUrl = getBackgroundImageUrl($contest['image_url']);
                            }
                            ?>
                            <div style="background: white; border: 1px solid #e4e6e9; border-radius: 12px; overflow: hidden;">
                                <?php if ($contestImageUrl): ?>
                                    <img src="<?php echo h($contestImageUrl); ?>" style="width: 100%; max-height: 200px; object-fit: cover;" alt="Contest image">
                                <?php endif; ?>
                                <div style="padding: 20px;">
                                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 15px;">
                                        <div>
                                            <h4 style="margin: 0 0 5px 0; font-size: 18px;"><?php echo h($contest['title']); ?></h4>
                                            <span style="display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 12px; <?php echo $contest['is_active'] ? 'background: #d4edda; color: #155724;' : 'background: #f8d7da; color: #721c24;'; ?>">
                                                <?php echo $contest['is_active'] ? 'Active' : 'Inactive'; ?>
                                            </span>
                                            <?php 
                                            $loc = $contest['display_location'] ?? 'none';
                                            if ($loc !== 'none'): 
                                            ?>
                                            <span style="display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 12px; background: #e3f2fd; color: #1565c0; margin-left: 5px;">
                                                <?php 
                                                if ($loc === 'feed') echo 'In Feed';
                                                elseif ($loc === 'header') echo 'In Header';
                                                elseif ($loc === 'both') echo 'Feed + Header';
                                                ?>
                                            </span>
                                            <?php endif; ?>
                                            <span style="color: #65676b; font-size: 13px; margin-left: 10px;">Created: <?php echo date('M j, Y', strtotime($contest['created_at'])); ?></span>
                                            <?php if (!empty($contest['expires_at'])): ?>
                                                <?php 
                                                $isExpired = strtotime($contest['expires_at']) < time();
                                                ?>
                                                <span style="display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 12px; margin-left: 5px; <?php echo $isExpired ? 'background: #f8d7da; color: #721c24;' : 'background: #fff3cd; color: #856404;'; ?>">
                                                    <?php echo $isExpired ? 'Expired' : 'Expires: ' . date('M j, Y g:ia', strtotime($contest['expires_at'])); ?>
                                                </span>
                                            <?php endif; ?>
                                        </div>
                                        <div style="display: flex; gap: 8px;">
                                            <button type="button" onclick="editContest(<?php echo $contest['id']; ?>)" class="btn" style="background: #1877f2; color: white; padding: 8px 16px; border-radius: 6px; border: none; cursor: pointer;">Edit</button>
                                            <form method="POST" style="display: inline;" onsubmit="return confirm('Delete this contest?')">
                                                <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                                                <input type="hidden" name="action" value="delete_contest">
                                                <input type="hidden" name="contest_id" value="<?php echo $contest['id']; ?>">
                                                <button type="submit" class="btn btn-danger" style="padding: 8px 16px; border-radius: 6px;">Delete</button>
                                            </form>
                                        </div>
                                    </div>
                                    <div style="color: #333; line-height: 1.6; max-height: 150px; overflow: hidden;" class="contest-content">
                                        <?php echo $contest['content']; ?>
                                    </div>
                                </div>
                            </div>
                            
                            <!-- Edit Modal for this contest -->
                            <div id="editContestModal<?php echo $contest['id']; ?>" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; padding: 20px; overflow-y: auto;">
                                <div style="background: white; max-width: 800px; margin: 40px auto; border-radius: 12px; padding: 30px;">
                                    <h3 style="margin: 0 0 20px 0;">Edit Contest</h3>
                                    <form method="POST" enctype="multipart/form-data" onsubmit="return prepareContestSubmit(this, 'edit<?php echo $contest['id']; ?>')">
                                        <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                                        <input type="hidden" name="action" value="update_contest">
                                        <input type="hidden" name="contest_id" value="<?php echo $contest['id']; ?>">
                                        <input type="hidden" name="content" id="editContestContent<?php echo $contest['id']; ?>">
                                        
                                        <div class="form-group" style="margin-bottom: 15px;">
                                            <label style="font-weight: 600; margin-bottom: 8px; display: block;">Contest Title *</label>
                                            <input type="text" name="title" required value="<?php echo h($contest['title']); ?>" style="width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 16px;">
                                        </div>
                                        
                                        <div class="form-group" style="margin-bottom: 15px;">
                                            <label style="font-weight: 600; margin-bottom: 8px; display: block;">Contest Details</label>
                                            <div id="editContestEditor<?php echo $contest['id']; ?>" style="height: 250px; background: white; border: 1px solid #ddd; border-radius: 8px;"></div>
                                        </div>
                                        
                                        <div class="form-group" style="margin-bottom: 15px;">
                                            <label style="font-weight: 600; margin-bottom: 8px; display: block;">Replace Feed Image (optional)</label>
                                            <?php if ($contestImageUrl): ?>
                                                <img src="<?php echo h($contestImageUrl); ?>" style="max-width: 200px; max-height: 100px; margin-bottom: 10px; border-radius: 8px;">
                                            <?php endif; ?>
                                            <input type="file" name="image" accept="image/*" style="display: block; padding: 8px 0;">
                                        </div>
                                        
                                        <div style="background: #f8f9fa; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
                                            <h4 style="margin: 0 0 15px 0; font-size: 16px;">Display Options</h4>
                                            
                                            <div class="form-group" style="margin-bottom: 15px;">
                                                <label style="font-weight: 600; margin-bottom: 8px; display: block;">Display Location</label>
                                                <select name="display_location" id="editDisplayLocation<?php echo $contest['id']; ?>" onchange="toggleDisplayOptions('edit<?php echo $contest['id']; ?>')" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px;">
                                                    <option value="none" <?php echo ($contest['display_location'] ?? 'none') === 'none' ? 'selected' : ''; ?>>None (Save only)</option>
                                                    <option value="feed" <?php echo ($contest['display_location'] ?? '') === 'feed' ? 'selected' : ''; ?>>Show in Feed</option>
                                                    <option value="header" <?php echo ($contest['display_location'] ?? '') === 'header' ? 'selected' : ''; ?>>Show in Header</option>
                                                    <option value="both" <?php echo ($contest['display_location'] ?? '') === 'both' ? 'selected' : ''; ?>>Both Feed and Header</option>
                                                </select>
                                            </div>
                                            
                                            <?php 
                                            $showHeaderOpts = in_array($contest['display_location'] ?? '', ['header', 'both']);
                                            $contestIconUrl = '';
                                            if (!empty($contest['icon_url'])) {
                                                $contestIconUrl = getBackgroundImageUrl($contest['icon_url']);
                                            }
                                            ?>
                                            <div id="editHeaderOptions<?php echo $contest['id']; ?>" style="<?php echo $showHeaderOpts ? '' : 'display: none;'; ?> margin-top: 15px; padding: 15px; background: white; border-radius: 6px; border: 1px solid #ddd;">
                                                <h5 style="margin: 0 0 12px 0; color: #333;">Header Icon Settings</h5>
                                                
                                                <div class="form-group" style="margin-bottom: 12px;">
                                                    <label style="font-weight: 500; margin-bottom: 6px; display: block;">Header Icon</label>
                                                    <?php if ($contestIconUrl): ?>
                                                        <img src="<?php echo h($contestIconUrl); ?>" style="width: 44px; height: 44px; border-radius: 50%; margin-bottom: 8px; background: #1a1a2e;">
                                                    <?php endif; ?>
                                                    <input type="file" name="icon" accept="image/*" style="padding: 6px 0;">
                                                    <small style="color: #65676b; font-size: 12px;">44x44 pixels recommended</small>
                                                </div>
                                                
                                                <div class="form-group" style="margin-bottom: 12px;">
                                                    <label style="font-weight: 500; margin-bottom: 6px; display: block;">Header Title</label>
                                                    <input type="text" name="header_title" value="<?php echo h($contest['header_title'] ?? ''); ?>" placeholder="e.g., Contest" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                                                </div>
                                                
                                                <div style="display: flex; gap: 15px;">
                                                    <div class="form-group" style="flex: 1;">
                                                        <label style="font-weight: 500; margin-bottom: 6px; display: block;">Title Color</label>
                                                        <input type="color" name="header_title_color" value="<?php echo h($contest['header_title_color'] ?? '#00ffff'); ?>" style="width: 60px; height: 35px; border: 1px solid #ddd; border-radius: 4px; cursor: pointer;">
                                                    </div>
                                                    <div class="form-group" style="flex: 1;">
                                                        <label style="font-weight: 500; margin-bottom: 6px; display: block;">Title Size</label>
                                                        <select name="header_title_size" style="padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                                                            <option value="10px" <?php echo ($contest['header_title_size'] ?? '12px') === '10px' ? 'selected' : ''; ?>>Small (10px)</option>
                                                            <option value="12px" <?php echo ($contest['header_title_size'] ?? '12px') === '12px' ? 'selected' : ''; ?>>Medium (12px)</option>
                                                            <option value="14px" <?php echo ($contest['header_title_size'] ?? '12px') === '14px' ? 'selected' : ''; ?>>Large (14px)</option>
                                                        </select>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                        
                                        <div class="form-group" style="margin-bottom: 20px;">
                                            <label style="font-weight: 600; margin-bottom: 8px; display: block;">Expiration Date</label>
                                            <?php 
                                            $expiresValue = '';
                                            if (!empty($contest['expires_at'])) {
                                                $expiresValue = date('Y-m-d\TH:i', strtotime($contest['expires_at']));
                                            }
                                            ?>
                                            <input type="datetime-local" name="expires_at" value="<?php echo $expiresValue; ?>" style="width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 14px;">
                                            <small style="display: block; color: #65676b; margin-top: 5px;">Leave empty for no expiration.</small>
                                        </div>
                                        
                                        <div class="form-group" style="margin-bottom: 20px;">
                                            <label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">
                                                <input type="checkbox" name="is_active" <?php echo $contest['is_active'] ? 'checked' : ''; ?> style="width: 18px; height: 18px;">
                                                <span style="font-weight: 600;">Active</span>
                                            </label>
                                        </div>
                                        
                                        <div style="display: flex; gap: 12px;">
                                            <button type="submit" class="btn btn-primary" style="padding: 12px 24px;">Save Changes</button>
                                            <button type="button" onclick="closeEditModal(<?php echo $contest['id']; ?>)" class="btn" style="background: #e4e6e9; color: #333; padding: 12px 24px; border: none; border-radius: 6px; cursor: pointer;">Cancel</button>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                
                <!-- Include Quill.js for rich text editing -->
                <link href="https://cdn.quilljs.com/1.3.7/quill.snow.css" rel="stylesheet">
                <script src="https://cdn.quilljs.com/1.3.7/quill.min.js"></script>
                
                <script>
                // Initialize add contest editor
                var addContestQuill = new Quill('#addContestEditor', {
                    theme: 'snow',
                    placeholder: 'Enter contest details, rules, prizes...',
                    modules: {
                        toolbar: [
                            [{ 'header': [1, 2, 3, false] }],
                            ['bold', 'italic', 'underline', 'strike'],
                            [{ 'color': [] }, { 'background': [] }],
                            [{ 'list': 'ordered'}, { 'list': 'bullet' }],
                            [{ 'align': [] }],
                            ['link'],
                            ['clean']
                        ]
                    }
                });
                
                // Store contest content for edit modals
                var contestContents = {
                    <?php foreach ($contests as $contest): ?>
                    <?php echo $contest['id']; ?>: <?php echo json_encode($contest['content']); ?>,
                    <?php endforeach; ?>
                };
                
                var editQuills = {};
                
                function editContest(contestId) {
                    document.getElementById('editContestModal' + contestId).style.display = 'block';
                    
                    // Initialize Quill editor if not already done
                    if (!editQuills[contestId]) {
                        editQuills[contestId] = new Quill('#editContestEditor' + contestId, {
                            theme: 'snow',
                            modules: {
                                toolbar: [
                                    [{ 'header': [1, 2, 3, false] }],
                                    ['bold', 'italic', 'underline', 'strike'],
                                    [{ 'color': [] }, { 'background': [] }],
                                    [{ 'list': 'ordered'}, { 'list': 'bullet' }],
                                    [{ 'align': [] }],
                                    ['link'],
                                    ['clean']
                                ]
                            }
                        });
                        
                        // Set initial content
                        if (contestContents[contestId]) {
                            editQuills[contestId].root.innerHTML = contestContents[contestId];
                        }
                    }
                }
                
                function closeEditModal(contestId) {
                    document.getElementById('editContestModal' + contestId).style.display = 'none';
                }
                
                function toggleDisplayOptions(prefix) {
                    var selectId = prefix === 'add' ? 'addDisplayLocation' : 'editDisplayLocation' + prefix.replace('edit', '');
                    var optionsId = prefix === 'add' ? 'addHeaderOptions' : 'editHeaderOptions' + prefix.replace('edit', '');
                    
                    var select = document.getElementById(selectId);
                    var options = document.getElementById(optionsId);
                    
                    if (select && options) {
                        var value = select.value;
                        if (value === 'header' || value === 'both') {
                            options.style.display = 'block';
                        } else {
                            options.style.display = 'none';
                        }
                    }
                }
                
                function prepareContestSubmit(form, type) {
                    if (type === 'add') {
                        document.getElementById('addContestContent').value = addContestQuill.root.innerHTML;
                    } else {
                        var contestId = type.replace('edit', '');
                        document.getElementById('editContestContent' + contestId).value = editQuills[contestId].root.innerHTML;
                    }
                    return true;
                }
                
                // Close modal when clicking outside
                document.addEventListener('click', function(e) {
                    if (e.target.id && e.target.id.startsWith('editContestModal')) {
                        e.target.style.display = 'none';
                    }
                });
                </script>
                
                <style>
                .ql-editor {
                    min-height: 200px;
                    font-size: 15px;
                }
                .ql-toolbar {
                    border-top-left-radius: 8px;
                    border-top-right-radius: 8px;
                    background: #f8f9fa;
                }
                .ql-container {
                    border-bottom-left-radius: 8px;
                    border-bottom-right-radius: 8px;
                }
                .contest-content h1, .contest-content h2, .contest-content h3 {
                    margin: 0.5em 0;
                }
                .contest-content p {
                    margin: 0.5em 0;
                }
                .contest-content ul, .contest-content ol {
                    padding-left: 20px;
                }
                </style>

            <?php elseif ($activeTab === 'polls'): ?>
                <?php
                // Get all polls
                $pollsStmt = $pdo->query("
                    SELECT p.*, 
                           (SELECT COUNT(*) FROM poll_votes WHERE poll_id = p.id) as total_votes,
                           (SELECT COUNT(*) FROM poll_options WHERE poll_id = p.id) as option_count
                    FROM polls p 
                    ORDER BY p.created_at DESC
                ");
                $allPolls = $pollsStmt->fetchAll();
                ?>
                
                <h2>Poll Management</h2>
                <p style="color: #65676b; margin-bottom: 20px;">Create and manage community polls.</p>
                
                <?php if (isset($_GET['poll_added'])): ?>
                    <div class="alert alert-success">Poll created successfully!</div>
                <?php endif; ?>
                <?php if (isset($_GET['poll_deleted'])): ?>
                    <div class="alert alert-success">Poll deleted successfully!</div>
                <?php endif; ?>
                
                <!-- Add New Poll Form -->
                <div style="background: white; border: 1px solid #e4e6e9; border-radius: 12px; padding: 24px; margin-bottom: 30px;">
                    <h3 style="margin: 0 0 20px 0; font-size: 18px;">Create New Poll</h3>
                    <form id="createPollForm">
                        <div class="form-group" style="margin-bottom: 15px;">
                            <label style="font-weight: 600; margin-bottom: 8px; display: block;">Poll Question *</label>
                            <input type="text" id="pollTitle" required style="width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 16px;" placeholder="What would you like to ask?">
                        </div>
                        
                        <div class="form-group" style="margin-bottom: 15px;">
                            <label style="font-weight: 600; margin-bottom: 8px; display: block;">Description (optional)</label>
                            <textarea id="pollDescription" style="width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 14px; min-height: 80px;" placeholder="Add more context about your poll..."></textarea>
                        </div>
                        
                        <div class="form-group" style="margin-bottom: 15px;">
                            <label style="font-weight: 600; margin-bottom: 8px; display: block;">Options *</label>
                            <div id="pollOptionsContainer">
                                <div class="poll-option-input" style="display: flex; gap: 8px; margin-bottom: 8px;">
                                    <input type="text" class="poll-option" required style="flex: 1; padding: 10px; border: 1px solid #ddd; border-radius: 6px;" placeholder="Option 1">
                                </div>
                                <div class="poll-option-input" style="display: flex; gap: 8px; margin-bottom: 8px;">
                                    <input type="text" class="poll-option" required style="flex: 1; padding: 10px; border: 1px solid #ddd; border-radius: 6px;" placeholder="Option 2">
                                </div>
                            </div>
                            <button type="button" onclick="addPollOption()" style="background: #e4e6e9; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; margin-top: 8px;">+ Add Option</button>
                        </div>
                        
                        <div style="display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 15px;">
                            <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                <input type="checkbox" id="pollAllowMultiple" style="width: 18px; height: 18px;">
                                <span>Allow multiple choices</span>
                            </label>
                            <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                <input type="checkbox" id="pollShowResultsBefore" style="width: 18px; height: 18px;">
                                <span>Show results before voting</span>
                            </label>
                        </div>
                        
                        <div class="form-group" style="margin-bottom: 20px;">
                            <label style="font-weight: 600; margin-bottom: 8px; display: block;">Expiration Date</label>
                            <input type="datetime-local" id="pollExpiresAt" style="width: 100%; max-width: 300px; padding: 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 14px;">
                            <small style="display: block; color: #65676b; margin-top: 5px;">Leave empty for no expiration.</small>
                        </div>
                        
                        <button type="submit" class="btn btn-primary" style="padding: 12px 24px; font-size: 16px;">Create Poll</button>
                    </form>
                </div>
                
                <!-- Existing Polls -->
                <h3 style="margin: 0 0 15px 0;">Existing Polls (<?php echo count($allPolls); ?>)</h3>
                
                <?php if (empty($allPolls)): ?>
                    <p style="color: #65676b; padding: 40px; text-align: center; background: #f8f9fa; border-radius: 12px;">No polls created yet.</p>
                <?php else: ?>
                    <div style="display: grid; gap: 16px;">
                        <?php foreach ($allPolls as $poll): 
                            $optStmt = $pdo->prepare("SELECT * FROM poll_options WHERE poll_id = ? ORDER BY display_order, id");
                            $optStmt->execute([$poll['id']]);
                            $pollOptions = $optStmt->fetchAll();
                        ?>
                            <div style="background: white; border: 1px solid #e4e6e9; border-radius: 12px; padding: 20px;">
                                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
                                    <div>
                                        <h4 style="margin: 0 0 5px 0; font-size: 18px;"><?php echo h($poll['title']); ?></h4>
                                        <div style="display: flex; gap: 8px; flex-wrap: wrap; align-items: center;">
                                            <span style="display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 12px; <?php echo $poll['is_active'] ? 'background: #d4edda; color: #155724;' : 'background: #f8d7da; color: #721c24;'; ?>">
                                                <?php echo $poll['is_active'] ? 'Active' : 'Inactive'; ?>
                                            </span>
                                            <span style="color: #65676b; font-size: 13px;"><?php echo $poll['total_votes']; ?> votes</span>
                                            <span style="color: #65676b; font-size: 13px;"><?php echo $poll['option_count']; ?> options</span>
                                            <?php if (!empty($poll['expires_at'])): ?>
                                                <?php $isExpired = strtotime($poll['expires_at']) < time(); ?>
                                                <span style="display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 12px; <?php echo $isExpired ? 'background: #f8d7da; color: #721c24;' : 'background: #fff3cd; color: #856404;'; ?>">
                                                    <?php echo $isExpired ? 'Expired' : 'Expires: ' . date('M j, Y', strtotime($poll['expires_at'])); ?>
                                                </span>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                    <div style="display: flex; gap: 8px;">
                                        <button type="button" onclick="togglePoll(<?php echo $poll['id']; ?>)" class="btn" style="background: <?php echo $poll['is_active'] ? '#ffc107' : '#28a745'; ?>; color: <?php echo $poll['is_active'] ? '#000' : '#fff'; ?>; padding: 8px 16px; border-radius: 6px; border: none; cursor: pointer;">
                                            <?php echo $poll['is_active'] ? 'Deactivate' : 'Activate'; ?>
                                        </button>
                                        <button type="button" onclick="deletePoll(<?php echo $poll['id']; ?>)" class="btn btn-danger" style="padding: 8px 16px; border-radius: 6px;">Delete</button>
                                    </div>
                                </div>
                                <?php if (!empty($poll['description'])): ?>
                                    <p style="color: #65676b; font-size: 14px; margin-bottom: 12px;"><?php echo h($poll['description']); ?></p>
                                <?php endif; ?>
                                <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                                    <?php foreach ($pollOptions as $opt): 
                                        $percent = $poll['total_votes'] > 0 ? round(($opt['vote_count'] / $poll['total_votes']) * 100) : 0;
                                    ?>
                                        <div style="background: #f0f2f5; padding: 8px 12px; border-radius: 6px; font-size: 13px;">
                                            <?php echo h($opt['option_text']); ?> <span style="color: #6366f1; font-weight: 600;">(<?php echo $percent; ?>%)</span>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                
                <script>
                function addPollOption() {
                    const container = document.getElementById('pollOptionsContainer');
                    const count = container.querySelectorAll('.poll-option-input').length + 1;
                    const div = document.createElement('div');
                    div.className = 'poll-option-input';
                    div.style.cssText = 'display: flex; gap: 8px; margin-bottom: 8px;';
                    div.innerHTML = `
                        <input type="text" class="poll-option" required style="flex: 1; padding: 10px; border: 1px solid #ddd; border-radius: 6px;" placeholder="Option ${count}">
                        <button type="button" onclick="this.parentElement.remove()" style="background: #e53e3e; color: white; border: none; padding: 8px 12px; border-radius: 6px; cursor: pointer;">X</button>
                    `;
                    container.appendChild(div);
                }
                
                document.getElementById('createPollForm').addEventListener('submit', async function(e) {
                    e.preventDefault();
                    
                    const title = document.getElementById('pollTitle').value.trim();
                    const description = document.getElementById('pollDescription').value.trim();
                    const options = Array.from(document.querySelectorAll('.poll-option')).map(el => el.value.trim()).filter(v => v);
                    const allowMultiple = document.getElementById('pollAllowMultiple').checked;
                    const showResultsBeforeVote = document.getElementById('pollShowResultsBefore').checked;
                    const expiresAt = document.getElementById('pollExpiresAt').value || null;
                    
                    if (!title || options.length < 2) {
                        alert('Please enter a question and at least 2 options');
                        return;
                    }
                    
                    try {
                        const response = await fetch('api/polls.php', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                action: 'create',
                                title,
                                description,
                                options,
                                allow_multiple: allowMultiple,
                                show_results_before_vote: showResultsBeforeVote,
                                expires_at: expiresAt
                            })
                        });
                        const data = await response.json();
                        if (data.success) {
                            window.location.href = '?tab=polls&poll_added=1';
                        } else {
                            alert(data.error || 'Failed to create poll');
                        }
                    } catch (err) {
                        alert('Failed to create poll');
                    }
                });
                
                async function togglePoll(pollId) {
                    try {
                        const response = await fetch('api/polls.php', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({action: 'toggle', poll_id: pollId})
                        });
                        const data = await response.json();
                        if (data.success) {
                            location.reload();
                        } else {
                            alert(data.error || 'Failed to toggle poll');
                        }
                    } catch (err) {
                        alert('Failed to toggle poll');
                    }
                }
                
                async function deletePoll(pollId) {
                    if (!confirm('Delete this poll and all votes?')) return;
                    try {
                        const response = await fetch('api/polls.php', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({action: 'delete', poll_id: pollId})
                        });
                        const data = await response.json();
                        if (data.success) {
                            window.location.href = '?tab=polls&poll_deleted=1';
                        } else {
                            alert(data.error || 'Failed to delete poll');
                        }
                    } catch (err) {
                        alert('Failed to delete poll');
                    }
                }
                </script>

            <?php elseif ($activeTab === 'bands'): ?>
                <?php
                $pendingBands = [];
                $verifiedBands = [];
                try {
                    $stmt = $pdo->query("
                        SELECT b.*, 
                               COALESCE(u.first_name, 'Deleted') as first_name, 
                               COALESCE(u.last_name, 'User') as last_name, 
                               COALESCE(u.email, 'N/A') as creator_email
                        FROM bands b
                        LEFT JOIN users u ON b.created_by = u.id
                        WHERE b.verification_status = 'pending'
                        ORDER BY b.created_at DESC
                    ");
                    $pendingBands = $stmt->fetchAll();
                    
                    $stmt = $pdo->query("
                        SELECT b.*, 
                               COALESCE(u.first_name, 'Deleted') as first_name, 
                               COALESCE(u.last_name, 'User') as last_name, 
                               COALESCE(u.email, 'N/A') as creator_email,
                               (SELECT COUNT(*) FROM band_followers WHERE band_id = b.id) as followers,
                               (SELECT COUNT(*) FROM band_tracks WHERE band_id = b.id) as tracks
                        FROM bands b
                        LEFT JOIN users u ON b.created_by = u.id
                        WHERE b.verification_status != 'pending'
                        ORDER BY b.created_at DESC
                    ");
                    $verifiedBands = $stmt->fetchAll();
                } catch (Exception $e) {
                    error_log('Error fetching bands: ' . $e->getMessage());
                }
                ?>
                
                <h2>Band Management</h2>
                <p style="color: #65676b; margin-bottom: 20px;">Verify and manage band accounts.</p>
                
                <?php if (isset($_GET['band_verified'])): ?>
                    <div class="alert alert-success">Band verified successfully!</div>
                <?php endif; ?>
                <?php if (isset($_GET['band_rejected'])): ?>
                    <div class="alert alert-success">Band rejected.</div>
                <?php endif; ?>
                <?php if (isset($_GET['band_deleted'])): ?>
                    <div class="alert alert-success">Band deleted successfully!</div>
                <?php endif; ?>
                
                <h3 style="margin-top: 30px; color: #d97706;">Pending Verification (<?php echo count($pendingBands); ?>)</h3>
                <?php if (count($pendingBands) > 0): ?>
                    <table style="width: 100%; border-collapse: collapse; margin-bottom: 40px;">
                        <thead>
                            <tr style="background: #fef3c7; text-align: left;">
                                <th style="padding: 12px; border-bottom: 2px solid #ddd;">Band Name</th>
                                <th style="padding: 12px; border-bottom: 2px solid #ddd;">Genre</th>
                                <th style="padding: 12px; border-bottom: 2px solid #ddd;">Location</th>
                                <th style="padding: 12px; border-bottom: 2px solid #ddd;">Created By</th>
                                <th style="padding: 12px; border-bottom: 2px solid #ddd;">Submitted</th>
                                <th style="padding: 12px; border-bottom: 2px solid #ddd; text-align: center;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($pendingBands as $band): ?>
                            <tr style="border-bottom: 1px solid #e4e6e9;">
                                <td style="padding: 12px;">
                                    <strong><?php echo h($band['name']); ?></strong>
                                    <?php if (!empty($band['website_url'])): ?>
                                        <br><a href="<?php echo h($band['website_url']); ?>" target="_blank" style="font-size: 12px; color: #1877f2;">Website</a>
                                    <?php endif; ?>
                                </td>
                                <td style="padding: 12px; color: #65676b;"><?php echo h($band['genre'] ?? 'N/A'); ?></td>
                                <td style="padding: 12px; color: #65676b;"><?php echo h($band['location'] ?? 'N/A'); ?></td>
                                <td style="padding: 12px;">
                                    <?php echo h($band['first_name'] . ' ' . $band['last_name']); ?>
                                    <br><span style="font-size: 12px; color: #65676b;"><?php echo h($band['creator_email']); ?></span>
                                </td>
                                <td style="padding: 12px; color: #65676b; font-size: 13px;">
                                    <?php echo date('M j, Y', strtotime($band['created_at'])); ?>
                                </td>
                                <td style="padding: 12px; text-align: center;">
                                    <div style="display: flex; gap: 8px; justify-content: center;">
                                        <form method="POST" style="margin: 0;">
                                            <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                                            <input type="hidden" name="action" value="verify_band">
                                            <input type="hidden" name="band_id" value="<?php echo $band['id']; ?>">
                                            <button type="submit" class="btn btn-success" style="font-size: 12px;">Verify</button>
                                        </form>
                                        <form method="POST" style="margin: 0;">
                                            <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                                            <input type="hidden" name="action" value="reject_band">
                                            <input type="hidden" name="band_id" value="<?php echo $band['id']; ?>">
                                            <button type="submit" class="btn btn-danger" style="font-size: 12px;">Reject</button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php else: ?>
                    <p style="color: #65676b; padding: 20px; background: #fef3c7; border-radius: 8px; margin-bottom: 30px;">No bands pending verification.</p>
                <?php endif; ?>
                
                <h3 style="margin-top: 30px;">All Bands (<?php echo count($verifiedBands); ?>)</h3>
                <?php if (count($verifiedBands) > 0): ?>
                    <table style="width: 100%; border-collapse: collapse;">
                        <thead>
                            <tr style="background: #f0f2f5; text-align: left;">
                                <th style="padding: 12px; border-bottom: 2px solid #ddd;">Band Name</th>
                                <th style="padding: 12px; border-bottom: 2px solid #ddd;">Genre</th>
                                <th style="padding: 12px; border-bottom: 2px solid #ddd;">Location</th>
                                <th style="padding: 12px; border-bottom: 2px solid #ddd;">Followers</th>
                                <th style="padding: 12px; border-bottom: 2px solid #ddd;">Tracks</th>
                                <th style="padding: 12px; border-bottom: 2px solid #ddd; text-align: center;">Status</th>
                                <th style="padding: 12px; border-bottom: 2px solid #ddd; text-align: center;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($verifiedBands as $band): ?>
                            <tr style="border-bottom: 1px solid #e4e6e9;">
                                <td style="padding: 12px;">
                                    <a href="band-profile.php?slug=<?php echo urlencode($band['slug']); ?>" target="_blank" style="color: #1877f2; font-weight: 600;">
                                        <?php echo h($band['name']); ?>
                                    </a>
                                </td>
                                <td style="padding: 12px; color: #65676b;"><?php echo h($band['genre'] ?? 'N/A'); ?></td>
                                <td style="padding: 12px; color: #65676b;"><?php echo h($band['location'] ?? 'N/A'); ?></td>
                                <td style="padding: 12px; color: #65676b;"><?php echo number_format($band['followers']); ?></td>
                                <td style="padding: 12px; color: #65676b;"><?php echo $band['tracks']; ?></td>
                                <td style="padding: 12px; text-align: center;">
                                    <?php if ($band['is_verified']): ?>
                                        <span style="padding: 4px 10px; background: #d4edda; color: #155724; border-radius: 12px; font-size: 12px;">Verified</span>
                                    <?php elseif ($band['verification_status'] === 'rejected'): ?>
                                        <span style="padding: 4px 10px; background: #ffe5e5; color: #e41e3f; border-radius: 12px; font-size: 12px;">Rejected</span>
                                    <?php else: ?>
                                        <span style="padding: 4px 10px; background: #e4e6e9; color: #333; border-radius: 12px; font-size: 12px;"><?php echo h($band['verification_status']); ?></span>
                                    <?php endif; ?>
                                </td>
                                <td style="padding: 12px; text-align: center;">
                                    <div style="display: flex; gap: 8px; justify-content: center;">
                                        <?php if (!$band['is_verified']): ?>
                                            <form method="POST" style="margin: 0;">
                                                <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                                                <input type="hidden" name="action" value="verify_band">
                                                <input type="hidden" name="band_id" value="<?php echo $band['id']; ?>">
                                                <button type="submit" class="btn btn-success" style="font-size: 12px;">Verify</button>
                                            </form>
                                        <?php endif; ?>
                                        <form method="POST" style="margin: 0;" onsubmit="return confirm('Delete this band permanently?');">
                                            <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                                            <input type="hidden" name="action" value="delete_band">
                                            <input type="hidden" name="band_id" value="<?php echo $band['id']; ?>">
                                            <button type="submit" class="btn btn-danger" style="font-size: 12px;">Delete</button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php else: ?>
                    <p style="color: #65676b; padding: 20px; background: #f0f2f5; border-radius: 8px;">No bands registered yet.</p>
                <?php endif; ?>

            <?php elseif ($activeTab === 'genres'): ?>
                <?php
                $allGenres = [];
                try {
                    $stmt = $pdo->query("SELECT * FROM band_genres ORDER BY display_order ASC, name ASC");
                    $allGenres = $stmt->fetchAll();
                } catch (Exception $e) {
                    error_log('Error fetching genres: ' . $e->getMessage());
                }
                ?>
                
                <h2>Band Genres Management</h2>
                <p style="color: #65676b; margin-bottom: 20px;">Manage the genres available for bands to select from.</p>
                
                <?php if (isset($_GET['genre_added'])): ?>
                    <div class="alert alert-success">Genre added successfully!</div>
                <?php endif; ?>
                <?php if (isset($_GET['genre_updated'])): ?>
                    <div class="alert alert-success">Genre updated successfully!</div>
                <?php endif; ?>
                <?php if (isset($_GET['genre_deleted'])): ?>
                    <div class="alert alert-success">Genre deleted successfully!</div>
                <?php endif; ?>
                <?php if (isset($_GET['genre_error']) && $_GET['genre_error'] === 'duplicate'): ?>
                    <div class="alert" style="background: #ffe5e5; color: #e41e3f;">A genre with this name already exists.</div>
                <?php endif; ?>
                <?php if (isset($_GET['genre_error']) && $_GET['genre_error'] === 'empty'): ?>
                    <div class="alert" style="background: #ffe5e5; color: #e41e3f;">Genre name cannot be empty.</div>
                <?php endif; ?>
                
                <div style="background: #f8f9fa; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 30px;">
                    <h3 style="margin: 0 0 15px 0; font-size: 16px; color: #333;">Add New Genre</h3>
                    <form method="POST" style="display: flex; flex-wrap: wrap; gap: 15px; align-items: flex-end;">
                        <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                        <input type="hidden" name="action" value="add_genre">
                        <div style="flex: 1; min-width: 200px;">
                            <label style="display: block; font-size: 13px; color: #666; margin-bottom: 5px;">Genre Name *</label>
                            <input type="text" name="genre_name" required placeholder="e.g., Ska, Reggae, Grunge" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px;">
                        </div>
                        <div style="width: 120px;">
                            <label style="display: block; font-size: 13px; color: #666; margin-bottom: 5px;">Display Order</label>
                            <input type="number" name="display_order" value="0" min="0" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px;">
                        </div>
                        <button type="submit" class="btn btn-primary" style="padding: 10px 20px;">Add Genre</button>
                    </form>
                </div>
                
                <h3>All Genres (<?php echo count($allGenres); ?>)</h3>
                <?php if (count($allGenres) > 0): ?>
                    <table style="width: 100%; border-collapse: collapse;">
                        <thead>
                            <tr style="background: #f0f2f5; text-align: left;">
                                <th style="padding: 12px; border-bottom: 2px solid #ddd;">Name</th>
                                <th style="padding: 12px; border-bottom: 2px solid #ddd;">Slug</th>
                                <th style="padding: 12px; border-bottom: 2px solid #ddd; text-align: center;">Display Order</th>
                                <th style="padding: 12px; border-bottom: 2px solid #ddd; text-align: center;">Active</th>
                                <th style="padding: 12px; border-bottom: 2px solid #ddd; text-align: center;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($allGenres as $genre): ?>
                            <tr style="border-bottom: 1px solid #e4e6e9;">
                                <td style="padding: 12px;">
                                    <strong><?php echo h($genre['name']); ?></strong>
                                </td>
                                <td style="padding: 12px; color: #65676b; font-family: monospace;"><?php echo h($genre['slug']); ?></td>
                                <td style="padding: 12px; text-align: center;"><?php echo $genre['display_order']; ?></td>
                                <td style="padding: 12px; text-align: center;">
                                    <?php if ($genre['is_active']): ?>
                                        <span style="padding: 4px 10px; background: #d4edda; color: #155724; border-radius: 12px; font-size: 12px;">Active</span>
                                    <?php else: ?>
                                        <span style="padding: 4px 10px; background: #e4e6e9; color: #666; border-radius: 12px; font-size: 12px;">Inactive</span>
                                    <?php endif; ?>
                                </td>
                                <td style="padding: 12px; text-align: center;">
                                    <div style="display: flex; gap: 8px; justify-content: center;">
                                        <button type="button" class="btn btn-secondary" style="font-size: 12px;" onclick="editGenre(<?php echo $genre['id']; ?>, '<?php echo h(addslashes($genre['name'])); ?>', <?php echo $genre['display_order']; ?>, <?php echo $genre['is_active'] ? 'true' : 'false'; ?>)">Edit</button>
                                        <form method="POST" style="margin: 0;" onsubmit="return confirm('Delete this genre? Bands with this genre will not lose their genre setting.');">
                                            <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                                            <input type="hidden" name="action" value="delete_genre">
                                            <input type="hidden" name="genre_id" value="<?php echo $genre['id']; ?>">
                                            <button type="submit" class="btn btn-danger" style="font-size: 12px;">Delete</button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php else: ?>
                    <p style="color: #65676b; padding: 20px; background: #f0f2f5; border-radius: 8px;">No genres defined yet.</p>
                <?php endif; ?>
                
                <div id="editGenreModal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; align-items: center; justify-content: center;">
                    <div style="background: white; padding: 30px; border-radius: 12px; max-width: 400px; width: 90%;">
                        <h3 style="margin: 0 0 20px 0;">Edit Genre</h3>
                        <form method="POST" id="editGenreForm">
                            <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                            <input type="hidden" name="action" value="update_genre">
                            <input type="hidden" name="genre_id" id="editGenreId">
                            <div style="margin-bottom: 15px;">
                                <label style="display: block; font-size: 13px; color: #666; margin-bottom: 5px;">Genre Name *</label>
                                <input type="text" name="genre_name" id="editGenreName" required style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; box-sizing: border-box;">
                            </div>
                            <div style="margin-bottom: 15px;">
                                <label style="display: block; font-size: 13px; color: #666; margin-bottom: 5px;">Display Order</label>
                                <input type="number" name="display_order" id="editGenreOrder" min="0" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; box-sizing: border-box;">
                            </div>
                            <div style="margin-bottom: 20px;">
                                <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                    <input type="checkbox" name="is_active" id="editGenreActive" value="1">
                                    <span>Active</span>
                                </label>
                            </div>
                            <div style="display: flex; gap: 10px; justify-content: flex-end;">
                                <button type="button" class="btn btn-secondary" onclick="closeEditGenreModal()">Cancel</button>
                                <button type="submit" class="btn btn-primary">Save Changes</button>
                            </div>
                        </form>
                    </div>
                </div>
                
                <script>
                function editGenre(id, name, order, isActive) {
                    document.getElementById('editGenreId').value = id;
                    document.getElementById('editGenreName').value = name;
                    document.getElementById('editGenreOrder').value = order;
                    document.getElementById('editGenreActive').checked = isActive;
                    document.getElementById('editGenreModal').style.display = 'flex';
                }
                
                function closeEditGenreModal() {
                    document.getElementById('editGenreModal').style.display = 'none';
                }
                
                document.getElementById('editGenreModal').addEventListener('click', function(e) {
                    if (e.target === this) closeEditGenreModal();
                });
                </script>

            <?php endif; ?>
        </div>
    </div>
    
    <script>
    // Table sorting for Users tab
    document.addEventListener('DOMContentLoaded', function() {
        const table = document.getElementById('usersTable');
        if (!table) return;
        
        const headers = table.querySelectorAll('th.sortable');
        let currentSort = { column: null, direction: 'asc' };
        
        headers.forEach(header => {
            header.addEventListener('click', function() {
                const column = this.dataset.column;
                const tbody = table.querySelector('tbody');
                const rows = Array.from(tbody.querySelectorAll('tr'));
                
                // Toggle direction
                if (currentSort.column === column) {
                    currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
                } else {
                    currentSort.column = column;
                    currentSort.direction = 'asc';
                }
                
                // Update header styling
                headers.forEach(h => h.classList.remove('asc', 'desc'));
                this.classList.add(currentSort.direction);
                
                // Sort rows
                rows.sort((a, b) => {
                    let aVal = a.dataset[column] || '';
                    let bVal = b.dataset[column] || '';
                    
                    // For date columns
                    if (column === 'joined') {
                        aVal = new Date(aVal).getTime();
                        bVal = new Date(bVal).getTime();
                    }
                    
                    // For boolean columns (active, admin, founder)
                    if (['active', 'admin', 'founder'].includes(column)) {
                        aVal = parseInt(aVal);
                        bVal = parseInt(bVal);
                    }
                    
                    if (aVal < bVal) return currentSort.direction === 'asc' ? -1 : 1;
                    if (aVal > bVal) return currentSort.direction === 'asc' ? 1 : -1;
                    return 0;
                });
                
                // Re-append sorted rows
                rows.forEach(row => tbody.appendChild(row));
            });
        });
    });
    </script>
    
    <!-- Edit Product Modal -->
    <div id="editProductModal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center;">
        <div style="background: white; border-radius: 12px; max-width: 900px; width: 95%; max-height: 95vh; overflow-y: auto; padding: 24px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h3 style="margin: 0;">Edit Product</h3>
                <button onclick="closeEditProductModal()" style="background: none; border: none; font-size: 24px; cursor: pointer; color: #65676b;">&times;</button>
            </div>
            <input type="hidden" id="editProductId">
            
            <!-- Custom Mockup Section -->
            <div class="form-group" style="margin-bottom: 20px;">
                <label style="font-weight: 600; margin-bottom: 10px; display: block;">Custom Mockup Image</label>
                <p style="color: #65676b; font-size: 13px; margin-bottom: 10px;">Upload your own mockup to use instead of Printify's default image. This will be shown in the feed and shop.</p>
                
                <div id="currentMockupPreview" style="display: none; margin-bottom: 15px; padding: 15px; background: #f0f2f5; border-radius: 8px;">
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <img id="mockupPreviewImg" src="" alt="Current mockup" style="width: 120px; height: 120px; object-fit: contain; border-radius: 6px; background: white;">
                        <div>
                            <p style="margin: 0 0 8px 0; font-weight: 500; color: #1a365d;">Current Custom Mockup</p>
                            <button type="button" onclick="removeCustomMockup()" style="padding: 6px 12px; background: #e41e3f; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">
                                Remove Custom Mockup
                            </button>
                        </div>
                    </div>
                </div>
                
                <div id="mockupUploadArea" style="border: 2px dashed #ddd; border-radius: 8px; padding: 30px; text-align: center; cursor: pointer; transition: all 0.2s;" 
                     onclick="document.getElementById('mockupFileInput').click()"
                     ondragover="event.preventDefault(); this.style.borderColor='#1877f2'; this.style.background='#f0f8ff';"
                     ondragleave="this.style.borderColor='#ddd'; this.style.background='transparent';"
                     ondrop="event.preventDefault(); this.style.borderColor='#ddd'; this.style.background='transparent'; handleMockupDrop(event);">
                    <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" fill="#65676b" viewBox="0 0 24 24" style="margin-bottom: 10px;">
                        <path d="M19 7V5c0-1.1-.9-2-2-2H7c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h10c1.1 0 2-.9 2-2v-2h-2v2H7V5h10v2h2zm-4 4V8l4 4-4 4v-3H9v-2h6z"/>
                    </svg>
                    <p style="margin: 0; color: #65676b;">Click or drag to upload custom mockup</p>
                    <p style="margin: 5px 0 0 0; color: #999; font-size: 12px;">JPG, PNG, GIF, WebP (max 10MB)</p>
                </div>
                <input type="file" id="mockupFileInput" accept="image/*" style="display: none;" onchange="handleMockupSelect(this)">
                <div id="mockupUploadProgress" style="display: none; margin-top: 10px;">
                    <div style="background: #e0e0e0; border-radius: 4px; overflow: hidden;">
                        <div id="mockupProgressBar" style="background: #1877f2; height: 4px; width: 0%; transition: width 0.3s;"></div>
                    </div>
                    <p style="margin: 5px 0 0 0; font-size: 12px; color: #65676b;">Uploading...</p>
                </div>
            </div>
            
            <!-- Feed Mockup Section -->
            <div class="form-group" style="margin-bottom: 20px; margin-top: 20px; padding-top: 20px; border-top: 1px solid #e4e6e9;">
                <label style="font-weight: 600; margin-bottom: 10px; display: block;">Feed Mockup Image</label>
                <p style="color: #65676b; font-size: 13px; margin-bottom: 10px;">Click an image below to set it as the feed mockup (shown in feed and as first modal image).</p>
                
                <div id="currentFeedMockupPreview" style="display: none; margin-bottom: 15px; padding: 15px; background: #fff3cd; border-radius: 8px;">
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <img id="feedMockupPreviewImg" src="" alt="Feed mockup" style="width: 120px; height: 120px; object-fit: contain; border-radius: 6px; background: white;">
                        <div>
                            <p style="margin: 0 0 8px 0; font-weight: 500; color: #856404;">Current Feed Mockup</p>
                            <button type="button" onclick="removeFeedMockup()" style="padding: 6px 12px; background: #e41e3f; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">
                                Remove Feed Mockup
                            </button>
                        </div>
                    </div>
                </div>
                
                <!-- Mockup Image Picker Gallery -->
                <div id="mockupPickerGallery" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)); gap: 10px; max-height: 300px; overflow-y: auto; padding: 10px; background: #f8f9fa; border-radius: 8px; border: 1px solid #e4e6e9;">
                    <p style="grid-column: 1/-1; text-align: center; color: #65676b;">Loading images...</p>
                </div>
                
                <p style="margin-top: 10px; font-size: 12px; color: #65676b;">Or upload your own image:</p>
                <div id="feedMockupUploadArea" style="border: 2px dashed #ffc107; border-radius: 8px; padding: 20px; text-align: center; cursor: pointer; transition: all 0.2s; background: #fffbeb; margin-top: 5px;" 
                     onclick="document.getElementById('feedMockupFileInput').click()"
                     ondragover="event.preventDefault(); this.style.borderColor='#1877f2'; this.style.background='#f0f8ff';"
                     ondragleave="this.style.borderColor='#ffc107'; this.style.background='#fffbeb';"
                     ondrop="event.preventDefault(); this.style.borderColor='#ffc107'; this.style.background='#fffbeb'; handleFeedMockupDrop(event);">
                    <p style="margin: 0; color: #856404; font-size: 13px;">Click or drag to upload custom image</p>
                </div>
                <input type="file" id="feedMockupFileInput" accept="image/*" style="display: none;" onchange="handleFeedMockupSelect(this)">
                <div id="feedMockupUploadProgress" style="display: none; margin-top: 10px;">
                    <div style="background: #e0e0e0; border-radius: 4px; overflow: hidden;">
                        <div id="feedMockupProgressBar" style="background: #ffc107; height: 4px; width: 0%; transition: width 0.3s;"></div>
                    </div>
                    <p style="margin: 5px 0 0 0; font-size: 12px; color: #65676b;">Uploading...</p>
                </div>
            </div>
            
            <!-- Sample Template Section -->
            <div class="form-group" style="margin-bottom: 20px; margin-top: 20px; padding-top: 20px; border-top: 1px solid #e4e6e9;">
                <label style="font-weight: 600; margin-bottom: 10px; display: block;">Sample Template Image</label>
                <p style="color: #65676b; font-size: 13px; margin-bottom: 10px;">Upload a sample image showing what the customization looks like. This is displayed above the canvas during customization.</p>
                
                <div id="currentSampleTemplatePreview" style="display: none; margin-bottom: 15px; padding: 15px; background: #e8f5e9; border-radius: 8px;">
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <img id="sampleTemplatePreviewImg" src="" alt="Sample template" style="width: 120px; height: 120px; object-fit: contain; border-radius: 6px; background: white;">
                        <div>
                            <p style="margin: 0 0 8px 0; font-weight: 500; color: #2e7d32;">Current Sample Template</p>
                            <button type="button" onclick="removeSampleTemplate()" style="padding: 6px 12px; background: #e41e3f; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">
                                Remove Sample Template
                            </button>
                        </div>
                    </div>
                </div>
                
                <div id="sampleTemplateUploadArea" style="border: 2px dashed #4caf50; border-radius: 8px; padding: 30px; text-align: center; cursor: pointer; transition: all 0.2s; background: #f1f8e9;" 
                     onclick="document.getElementById('sampleTemplateFileInput').click()"
                     ondragover="event.preventDefault(); this.style.borderColor='#1877f2'; this.style.background='#f0f8ff';"
                     ondragleave="this.style.borderColor='#4caf50'; this.style.background='#f1f8e9';"
                     ondrop="event.preventDefault(); this.style.borderColor='#4caf50'; this.style.background='#f1f8e9'; handleSampleTemplateDrop(event);">
                    <p style="margin: 0; color: #2e7d32; font-size: 13px;">Click or drag to upload sample template image</p>
                </div>
                <input type="file" id="sampleTemplateFileInput" accept="image/*" style="display: none;" onchange="handleSampleTemplateSelect(this)">
                <div id="sampleTemplateUploadProgress" style="display: none; margin-top: 10px;">
                    <div style="background: #e0e0e0; border-radius: 4px; overflow: hidden;">
                        <div id="sampleTemplateProgressBar" style="background: #4caf50; height: 4px; width: 0%; transition: width 0.3s;"></div>
                    </div>
                    <p style="margin: 5px 0 0 0; font-size: 12px; color: #65676b;">Uploading...</p>
                </div>
            </div>
            
            <!-- Customization Settings (only shown for customizable products) -->
            <div id="customizationSettingsSection" style="display: none; margin-top: 20px; padding: 20px; background: #fffbeb; border: 2px solid #ffc107; border-radius: 8px;">
                <h4 style="margin: 0 0 15px 0; color: #856404; display: flex; align-items: center; gap: 8px;">
                    <span style="font-size: 20px;">🎨</span> Customization Settings
                </h4>
                
                <!-- Design Template Upload -->
                <div style="margin-bottom: 20px;">
                    <label style="display: block; font-weight: 600; font-size: 13px; margin-bottom: 8px; color: #333;">Design Template (Transparent Overlay)</label>
                    <p style="color: #65676b; font-size: 12px; margin-bottom: 10px;">This is the transparent PNG that overlays the customer's uploaded image. The design area should be transparent.</p>
                    
                    <div id="currentDesignTemplatePreview" style="display: none; margin-bottom: 10px; padding: 12px; background: white; border-radius: 6px; border: 1px solid #ddd;">
                        <div style="display: flex; align-items: center; gap: 15px;">
                            <img id="designTemplatePreviewImg" src="" alt="Design template" style="width: 100px; height: 100px; object-fit: contain; border-radius: 4px; background: #f0f0f0;">
                            <div>
                                <p style="margin: 0 0 8px 0; font-weight: 500; color: #333;">Current Design Template</p>
                                <button type="button" onclick="removeDesignTemplate()" style="padding: 5px 10px; background: #e41e3f; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 11px;">Remove</button>
                            </div>
                        </div>
                    </div>
                    
                    <div id="designTemplateUploadArea" style="border: 2px dashed #856404; border-radius: 6px; padding: 20px; text-align: center; cursor: pointer; background: white;" 
                         onclick="document.getElementById('designTemplateFileInput').click()">
                        <p style="margin: 0; color: #856404; font-size: 12px;">Click to upload design template (PNG recommended)</p>
                    </div>
                    <input type="file" id="designTemplateFileInput" accept="image/*" style="display: none;" onchange="handleDesignTemplateSelect(this)">
                </div>
                
                <!-- Template Dimensions -->
                <div style="margin-bottom: 20px;">
                    <button type="button" onclick="toggleEditDimensions()" style="background: #f0f2f5; border: 1px solid #ddd; border-radius: 6px; padding: 10px 15px; cursor: pointer; font-size: 13px; width: 100%; text-align: left;">
                        <strong>Template Dimensions</strong> <span id="editDimensionsToggle" style="float: right;">+</span>
                    </button>
                    <div id="editDimensionsPanel" style="display: none; background: white; padding: 15px; border-radius: 0 0 6px 6px; border: 1px solid #ddd; border-top: none;">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px;">
                            <div>
                                <label style="font-size: 11px; color: #666;">Canvas Width (px)</label>
                                <input type="number" id="editCanvasWidth" value="500" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-size: 13px;">
                            </div>
                            <div>
                                <label style="font-size: 11px; color: #666;">Canvas Height (px)</label>
                                <input type="number" id="editCanvasHeight" value="600" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-size: 13px;">
                            </div>
                        </div>
                        <p style="font-size: 11px; color: #666; margin: 0 0 10px 0;"><strong>Target Area</strong> (where customer image appears)</p>
                        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 8px;">
                            <div>
                                <label style="font-size: 10px; color: #666;">X</label>
                                <input type="number" id="editTargetX" value="50" style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                            </div>
                            <div>
                                <label style="font-size: 10px; color: #666;">Y</label>
                                <input type="number" id="editTargetY" value="50" style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                            </div>
                            <div>
                                <label style="font-size: 10px; color: #666;">Width</label>
                                <input type="number" id="editTargetWidth" value="400" style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                            </div>
                            <div>
                                <label style="font-size: 10px; color: #666;">Height</label>
                                <input type="number" id="editTargetHeight" value="500" style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Mockup Placement -->
                <div style="margin-bottom: 20px;">
                    <button type="button" onclick="toggleEditMockupPlacement()" style="background: #e8f5e9; border: 1px solid #c8e6c9; border-radius: 6px; padding: 10px 15px; cursor: pointer; font-size: 13px; width: 100%; text-align: left;">
                        <strong>🖼️ Mockup Placement</strong> <span id="editMockupPlacementToggle" style="float: right;">+</span>
                    </button>
                    <div id="editMockupPlacementPanel" style="display: none; background: #f9fff9; padding: 15px; border-radius: 0 0 6px 6px; border: 1px solid #c8e6c9; border-top: none;">
                        <p style="font-size: 11px; color: #388e3c; margin: 0 0 10px 0;">
                            Where should the design appear on the mockup? (percentage values 0-100)
                        </p>
                        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 8px;">
                            <div>
                                <label style="font-size: 10px; color: #666;">X %</label>
                                <input type="number" id="editMockupX" value="25" min="0" max="100" style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                            </div>
                            <div>
                                <label style="font-size: 10px; color: #666;">Y %</label>
                                <input type="number" id="editMockupY" value="15" min="0" max="100" style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                            </div>
                            <div>
                                <label style="font-size: 10px; color: #666;">Width %</label>
                                <input type="number" id="editMockupWidth" value="50" min="1" max="100" style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                            </div>
                            <div>
                                <label style="font-size: 10px; color: #666;">Height %</label>
                                <input type="number" id="editMockupHeight" value="70" min="1" max="100" style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                            </div>
                        </div>
                        <p style="font-size: 10px; color: #666; margin: 8px 0 0 0;">Tip: For centered design, try X=25, Y=15, W=50, H=70</p>
                    </div>
                </div>
                
                <!-- Product Shape Selector -->
                <div style="margin-bottom: 20px; padding: 15px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 8px;">
                    <label style="display: block; font-weight: 600; font-size: 14px; margin-bottom: 8px; color: white;">Product Shape</label>
                    <p style="font-size: 11px; color: rgba(255,255,255,0.8); margin: 0 0 12px 0;">Select the type of product to show only relevant settings</p>
                    <div style="display: flex; gap: 12px;">
                        <label class="shape-option shape-selected" id="shapeFlat" onclick="selectProductShape('flat')" 
                               onmouseover="this.classList.add('shape-hover')" onmouseout="this.classList.remove('shape-hover')">
                            <input type="radio" name="productShape" value="flat" style="display: none;" checked>
                            <span class="shape-check">✓</span>
                            <div style="font-size: 28px; margin-bottom: 6px;">👕</div>
                            <div style="font-weight: 700; font-size: 13px; color: #333;">Flat</div>
                            <div style="font-size: 11px; color: #666; margin-top: 2px;">T-shirts, Bags, Prints</div>
                        </label>
                        <label class="shape-option" id="shapeRound" onclick="selectProductShape('round')"
                               onmouseover="this.classList.add('shape-hover')" onmouseout="this.classList.remove('shape-hover')">
                            <input type="radio" name="productShape" value="round" style="display: none;">
                            <span class="shape-check">✓</span>
                            <div style="font-size: 28px; margin-bottom: 6px;">🥤</div>
                            <div style="font-weight: 700; font-size: 13px; color: #333;">Round/Cylindrical</div>
                            <div style="font-size: 11px; color: #666; margin-top: 2px;">Tumblers, Mugs, Cups</div>
                        </label>
                    </div>
                </div>
                <style>
                    .shape-option {
                        flex: 1;
                        background: #f8f9fa;
                        border-radius: 8px;
                        padding: 15px;
                        cursor: pointer;
                        text-align: center;
                        border: 3px solid #e0e0e0;
                        transition: all 0.2s ease;
                        position: relative;
                    }
                    .shape-option .shape-check {
                        display: none;
                        position: absolute;
                        top: 8px;
                        right: 8px;
                        background: #22c55e;
                        color: white;
                        width: 22px;
                        height: 22px;
                        border-radius: 50%;
                        font-size: 14px;
                        font-weight: bold;
                        line-height: 22px;
                    }
                    .shape-option.shape-selected {
                        background: #ffffff;
                        border-color: #22c55e;
                        box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.2);
                    }
                    .shape-option.shape-selected .shape-check {
                        display: block;
                    }
                    .shape-option.shape-hover:not(.shape-selected) {
                        border-color: #a78bfa;
                        background: #faf5ff;
                    }
                </style>
                
                <!-- Feed Post Text -->
                <div style="margin-bottom: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px; border: 1px solid #e0e0e0;">
                    <label style="display: block; font-weight: 600; font-size: 14px; margin-bottom: 5px; color: #333;">📝 Feed Display Text</label>
                    <p style="font-size: 11px; color: #666; margin: 0 0 10px 0;">This text appears as the headline above the product image in the community feed</p>
                    <textarea id="editFeedText" placeholder="Custom text to display in feed (leave empty to use product name)..." style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px; resize: vertical; min-height: 60px; margin-bottom: 12px;"></textarea>
                    
                    <div style="background: white; padding: 12px; border-radius: 6px; border: 1px solid #ddd;">
                        <label style="display: block; font-weight: 600; font-size: 12px; margin-bottom: 10px; color: #555;">Text Styling Options</label>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                            <div>
                                <label style="font-size: 11px; color: #666; display: block; margin-bottom: 4px;">Font Family</label>
                                <select id="editFeedTextFont" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                    <option value="inherit">Default (System)</option>
                                    <option value="Georgia, serif">Georgia (Serif)</option>
                                    <option value="'Times New Roman', serif">Times New Roman</option>
                                    <option value="Arial, sans-serif">Arial</option>
                                    <option value="Helvetica, sans-serif">Helvetica</option>
                                    <option value="Verdana, sans-serif">Verdana</option>
                                    <option value="'Trebuchet MS', sans-serif">Trebuchet MS</option>
                                    <option value="Impact, sans-serif">Impact</option>
                                    <option value="'Comic Sans MS', cursive">Comic Sans MS</option>
                                    <option value="'Courier New', monospace">Courier New</option>
                                </select>
                            </div>
                            <div>
                                <label style="font-size: 11px; color: #666; display: block; margin-bottom: 4px;">Font Size</label>
                                <select id="editFeedTextSize" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                    <option value="14px">Small (14px)</option>
                                    <option value="16px">Medium (16px)</option>
                                    <option value="18px" selected>Large (18px)</option>
                                    <option value="20px">X-Large (20px)</option>
                                    <option value="24px">XX-Large (24px)</option>
                                    <option value="28px">Heading (28px)</option>
                                    <option value="32px">Display (32px)</option>
                                </select>
                            </div>
                            <div>
                                <label style="font-size: 11px; color: #666; display: block; margin-bottom: 4px;">Text Color</label>
                                <div style="display: flex; gap: 6px; align-items: center;">
                                    <input type="color" id="editFeedTextColor" value="#1c1e21" style="width: 40px; height: 32px; border: 1px solid #ddd; border-radius: 4px; cursor: pointer;">
                                    <input type="text" id="editFeedTextColorHex" value="#1c1e21" style="flex: 1; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 11px; font-family: monospace;" oninput="document.getElementById('editFeedTextColor').value = this.value">
                                </div>
                            </div>
                            <div>
                                <label style="font-size: 11px; color: #666; display: block; margin-bottom: 4px;">Font Weight</label>
                                <select id="editFeedTextWeight" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                                    <option value="400">Normal (400)</option>
                                    <option value="500">Medium (500)</option>
                                    <option value="600">Semi-Bold (600)</option>
                                    <option value="700" selected>Bold (700)</option>
                                    <option value="800">Extra-Bold (800)</option>
                                    <option value="900">Black (900)</option>
                                </select>
                            </div>
                        </div>
                        <div style="margin-top: 12px; padding: 10px; background: #f8f9fa; border-radius: 4px; border: 1px dashed #ccc;">
                            <label style="font-size: 10px; color: #888; display: block; margin-bottom: 4px;">PREVIEW</label>
                            <div id="feedTextPreview" style="font-size: 18px; font-weight: 700; color: #1c1e21;">Sample headline text preview</div>
                        </div>
                    </div>
                </div>
                <script>
                    document.getElementById('editFeedTextColor').addEventListener('input', function() {
                        document.getElementById('editFeedTextColorHex').value = this.value;
                        updateFeedTextPreview();
                    });
                    function updateFeedTextPreview() {
                        const preview = document.getElementById('feedTextPreview');
                        const text = document.getElementById('editFeedText').value || 'Sample headline text preview';
                        preview.textContent = text;
                        preview.style.fontFamily = document.getElementById('editFeedTextFont').value;
                        preview.style.fontSize = document.getElementById('editFeedTextSize').value;
                        preview.style.color = document.getElementById('editFeedTextColor').value;
                        preview.style.fontWeight = document.getElementById('editFeedTextWeight').value;
                    }
                    ['editFeedText', 'editFeedTextFont', 'editFeedTextSize', 'editFeedTextWeight'].forEach(id => {
                        document.getElementById(id)?.addEventListener('input', updateFeedTextPreview);
                        document.getElementById(id)?.addEventListener('change', updateFeedTextPreview);
                    });
                </script>
                
                <!-- Swap Size/Color Toggle -->
                <div style="margin-bottom: 20px; padding: 12px; background: #fff3cd; border-radius: 6px; border: 1px solid #ffc107;">
                    <label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">
                        <input type="checkbox" id="editSwapSizeColor" style="width: 18px; height: 18px; cursor: pointer;">
                        <span style="font-weight: 600; font-size: 13px; color: #856404;">🔄 Swap Size/Color Values</span>
                    </label>
                    <p style="margin: 8px 0 0 28px; font-size: 11px; color: #856404;">Enable if the product's size and color options appear swapped (e.g., colors showing as sizes).</p>
                </div>
                
                <!-- 360 Preview Toggle (only for round products) -->
                <div id="enable360Container" style="margin-bottom: 20px; padding: 12px; background: #f0f8ff; border-radius: 6px; border: 1px solid #b8daff; display: none;">
                    <label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">
                        <input type="checkbox" id="editEnable360" style="width: 18px; height: 18px; cursor: pointer;">
                        <span style="font-weight: 600; font-size: 13px; color: #0066cc;">Enable 360° 3D Preview</span>
                    </label>
                    <p style="margin: 8px 0 0 28px; font-size: 11px; color: #666;">Enable for cylindrical products (tumblers, mugs). Flat products will show 2D preview.</p>
                </div>
                
                <!-- 3D Measurements (only shown when 360 is enabled) -->
                <div id="edit3DMeasurementsSection" style="display: none; margin-bottom: 20px; padding: 15px; background: #fff8e6; border-radius: 6px; border: 1px solid #ffc107;">
                    <strong style="font-size: 12px; color: #856404;">📏 3D Product Measurements (inches)</strong>
                    <p style="font-size: 11px; color: #856404; margin: 5px 0 12px 0;">Enter exact dimensions for accurate 3D model</p>
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 10px;">
                        <div>
                            <label style="font-size: 10px; color: #666;">Height</label>
                            <input type="number" step="0.01" id="editProductHeight" placeholder="e.g. 6.5" style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                        </div>
                        <div>
                            <label style="font-size: 10px; color: #666;">Top Diameter</label>
                            <input type="number" step="0.01" id="editTopDiameter" placeholder="e.g. 3.5" style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                        </div>
                        <div>
                            <label style="font-size: 10px; color: #666;">Bottom Diameter</label>
                            <input type="number" step="0.01" id="editBottomDiameter" placeholder="e.g. 2.75" style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                        </div>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;">
                        <div>
                            <label style="font-size: 10px; color: #666;">Print Area Width</label>
                            <input type="number" step="0.01" id="editPrintAreaWidth" placeholder="e.g. 9.5" style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                        </div>
                        <div>
                            <label style="font-size: 10px; color: #666;">Print Area Height</label>
                            <input type="number" step="0.01" id="editPrintAreaHeight" placeholder="e.g. 3.5" style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                        </div>
                        <div>
                            <label style="font-size: 10px; color: #666;">Print Top Offset</label>
                            <input type="number" step="0.01" id="editPrintTopOffset" placeholder="e.g. 1.0" style="width: 100%; padding: 6px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px;">
                        </div>
                    </div>
                </div>
                
                <!-- Variant Blank Mockups -->
                <div id="editVariantMockupsSection" style="margin-top: 20px; padding: 15px; background: #f0f4f8; border-radius: 6px; border: 1px solid #d1e3f0;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                        <strong style="font-size: 12px; color: #2c5282;">🎨 Variant Blank Mockups</strong>
                        <button type="button" onclick="loadVariantMockups()" style="padding: 4px 10px; font-size: 11px; background: #4299e1; color: white; border: none; border-radius: 4px; cursor: pointer;">Refresh</button>
                    </div>
                    <p style="font-size: 11px; color: #4a5568; margin: 0 0 12px 0;">Upload blank product images for each color variant. These will be used for 3D preview.</p>
                    <div id="variantMockupsGrid" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 12px;">
                        <p style="color: #718096; font-size: 11px; grid-column: 1/-1; text-align: center; padding: 20px;">Loading variants...</p>
                    </div>
                </div>
            </div>
            
            <hr style="border: none; border-top: 1px solid #e4e6e9; margin: 20px 0;">
            
            <div class="form-group">
                <label for="editProductName">Product Name</label>
                <input type="text" id="editProductName" placeholder="Enter product name..." style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px;">
            </div>
            <div class="form-group" style="margin-top: 15px;">
                <label for="editProductDescription">Description (HTML allowed)</label>
                <textarea id="editProductDescription" rows="25" placeholder="Enter product description..." style="width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 6px; font-family: monospace; font-size: 13px; line-height: 1.5; min-height: 400px; resize: vertical;"></textarea>
            </div>
            <div style="display: flex; gap: 10px; justify-content: flex-end; margin-top: 20px;">
                <button type="button" class="btn btn-secondary" onclick="closeEditProductModal()">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="saveProductEdit()">Save Changes</button>
            </div>
        </div>
    </div>
    
    <script>
    // Custom mockup upload functions
    function handleMockupSelect(input) {
        if (input.files && input.files[0]) {
            uploadMockup(input.files[0]);
        }
    }
    
    function handleMockupDrop(e) {
        const files = e.dataTransfer.files;
        if (files && files[0]) {
            uploadMockup(files[0]);
        }
    }
    
    function uploadMockup(file) {
        const productId = document.getElementById('editProductId').value;
        if (!productId) {
            alert('Please save the product first before uploading a mockup.');
            return;
        }
        
        const formData = new FormData();
        formData.append('action', 'upload_mockup');
        formData.append('id', productId);
        formData.append('mockup', file);
        
        document.getElementById('mockupUploadProgress').style.display = 'block';
        document.getElementById('mockupProgressBar').style.width = '30%';
        
        fetch('api/pod-admin.php', {
            method: 'POST',
            body: formData
        })
        .then(r => r.json())
        .then(data => {
            document.getElementById('mockupProgressBar').style.width = '100%';
            setTimeout(() => {
                document.getElementById('mockupUploadProgress').style.display = 'none';
                document.getElementById('mockupProgressBar').style.width = '0%';
            }, 500);
            
            if (data.success) {
                showMockupPreview(data.mockup_url);
            } else {
                alert(data.error || 'Failed to upload mockup');
            }
        })
        .catch(err => {
            document.getElementById('mockupUploadProgress').style.display = 'none';
            console.error('Mockup upload error:', err);
            alert('Failed to upload mockup. Please try again.');
        });
    }
    
    function showMockupPreview(url) {
        document.getElementById('mockupPreviewImg').src = url;
        document.getElementById('currentMockupPreview').style.display = 'block';
    }
    
    function hideMockupPreview() {
        document.getElementById('currentMockupPreview').style.display = 'none';
        document.getElementById('mockupPreviewImg').src = '';
    }
    
    function removeCustomMockup() {
        if (!confirm('Remove custom mockup? The product will use Printify\'s default image.')) return;
        
        const productId = document.getElementById('editProductId').value;
        const formData = new FormData();
        formData.append('action', 'remove_mockup');
        formData.append('id', productId);
        
        fetch('api/pod-admin.php', {
            method: 'POST',
            body: formData
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                hideMockupPreview();
            } else {
                alert('Failed to remove mockup');
            }
        })
        .catch(err => {
            console.error('Remove mockup error:', err);
            alert('Failed to remove mockup. Please try again.');
        });
    }
    
    // Feed mockup upload functions
    function handleFeedMockupSelect(input) {
        if (input.files && input.files[0]) {
            uploadFeedMockup(input.files[0]);
        }
    }
    
    function handleFeedMockupDrop(e) {
        const files = e.dataTransfer.files;
        if (files && files[0]) {
            uploadFeedMockup(files[0]);
        }
    }
    
    function uploadFeedMockup(file) {
        const productId = document.getElementById('editProductId').value;
        if (!productId) {
            alert('Please save the product first before uploading a feed mockup.');
            return;
        }
        
        const formData = new FormData();
        formData.append('action', 'upload_feed_mockup');
        formData.append('id', productId);
        formData.append('mockup', file);
        
        document.getElementById('feedMockupUploadProgress').style.display = 'block';
        document.getElementById('feedMockupProgressBar').style.width = '30%';
        
        fetch('api/pod-admin.php', {
            method: 'POST',
            body: formData
        })
        .then(r => r.json())
        .then(data => {
            document.getElementById('feedMockupProgressBar').style.width = '100%';
            setTimeout(() => {
                document.getElementById('feedMockupUploadProgress').style.display = 'none';
                document.getElementById('feedMockupProgressBar').style.width = '0%';
            }, 500);
            
            if (data.success) {
                showFeedMockupPreview(data.feed_mockup_url);
            } else {
                alert(data.error || 'Failed to upload feed mockup');
            }
        })
        .catch(err => {
            document.getElementById('feedMockupUploadProgress').style.display = 'none';
            console.error('Feed mockup upload error:', err);
            alert('Failed to upload feed mockup. Please try again.');
        });
    }
    
    function showFeedMockupPreview(url) {
        document.getElementById('feedMockupPreviewImg').src = url;
        document.getElementById('currentFeedMockupPreview').style.display = 'block';
    }
    
    function hideFeedMockupPreview() {
        document.getElementById('currentFeedMockupPreview').style.display = 'none';
        document.getElementById('feedMockupPreviewImg').src = '';
    }
    
    function removeFeedMockup() {
        if (!confirm('Remove feed mockup? The product will use the custom mockup or default image in the feed.')) return;
        
        const productId = document.getElementById('editProductId').value;
        const formData = new FormData();
        formData.append('action', 'remove_feed_mockup');
        formData.append('id', productId);
        
        fetch('api/pod-admin.php', {
            method: 'POST',
            body: formData
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                hideFeedMockupPreview();
            } else {
                alert('Failed to remove feed mockup');
            }
        })
        .catch(err => {
            console.error('Remove feed mockup error:', err);
            alert('Failed to remove feed mockup. Please try again.');
        });
    }
    
    // Sample template upload functions
    function handleSampleTemplateSelect(input) {
        if (input.files && input.files[0]) {
            uploadSampleTemplate(input.files[0]);
        }
    }
    
    function handleSampleTemplateDrop(e) {
        const files = e.dataTransfer.files;
        if (files && files[0]) {
            uploadSampleTemplate(files[0]);
        }
    }
    
    function uploadSampleTemplate(file) {
        const productId = document.getElementById('editProductId').value;
        if (!productId) {
            alert('Please save the product first before uploading a sample template.');
            return;
        }
        
        const formData = new FormData();
        formData.append('action', 'upload_sample_template');
        formData.append('id', productId);
        formData.append('template', file);
        
        document.getElementById('sampleTemplateUploadProgress').style.display = 'block';
        document.getElementById('sampleTemplateProgressBar').style.width = '30%';
        
        fetch('api/pod-admin.php', {
            method: 'POST',
            body: formData
        })
        .then(r => r.json())
        .then(data => {
            document.getElementById('sampleTemplateProgressBar').style.width = '100%';
            setTimeout(() => {
                document.getElementById('sampleTemplateUploadProgress').style.display = 'none';
                document.getElementById('sampleTemplateProgressBar').style.width = '0%';
            }, 500);
            
            if (data.success) {
                showSampleTemplatePreview(data.sample_template_url);
            } else {
                alert(data.error || 'Failed to upload sample template');
            }
        })
        .catch(err => {
            document.getElementById('sampleTemplateUploadProgress').style.display = 'none';
            console.error('Sample template upload error:', err);
            alert('Failed to upload sample template. Please try again.');
        });
    }
    
    function showSampleTemplatePreview(url) {
        document.getElementById('sampleTemplatePreviewImg').src = url;
        document.getElementById('currentSampleTemplatePreview').style.display = 'block';
    }
    
    function hideSampleTemplatePreview() {
        document.getElementById('currentSampleTemplatePreview').style.display = 'none';
        document.getElementById('sampleTemplatePreviewImg').src = '';
    }
    
    function removeSampleTemplate() {
        if (!confirm('Remove sample template? This image will no longer appear in the customization preview.')) return;
        
        const productId = document.getElementById('editProductId').value;
        const formData = new FormData();
        formData.append('action', 'remove_sample_template');
        formData.append('id', productId);
        
        fetch('api/pod-admin.php', {
            method: 'POST',
            body: formData
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                hideSampleTemplatePreview();
            } else {
                alert('Failed to remove sample template');
            }
        })
        .catch(err => {
            console.error('Remove sample template error:', err);
            alert('Failed to remove sample template. Please try again.');
        });
    }
    
    // Customization settings functions
    function toggleEditDimensions() {
        const panel = document.getElementById('editDimensionsPanel');
        const toggle = document.getElementById('editDimensionsToggle');
        if (panel.style.display === 'none') {
            panel.style.display = 'block';
            toggle.textContent = '−';
        } else {
            panel.style.display = 'none';
            toggle.textContent = '+';
        }
    }
    
    function toggleEditMockupPlacement() {
        const panel = document.getElementById('editMockupPlacementPanel');
        const toggle = document.getElementById('editMockupPlacementToggle');
        if (panel.style.display === 'none') {
            panel.style.display = 'block';
            toggle.textContent = '−';
        } else {
            panel.style.display = 'none';
            toggle.textContent = '+';
        }
    }
    
    // Design template upload
    function handleDesignTemplateSelect(input) {
        if (input.files && input.files[0]) {
            uploadDesignTemplate(input.files[0]);
        }
    }
    
    function uploadDesignTemplate(file) {
        const productId = document.getElementById('editProductId').value;
        if (!productId) {
            alert('Please save the product first before uploading a design template.');
            return;
        }
        
        const formData = new FormData();
        formData.append('action', 'upload_design_template');
        formData.append('id', productId);
        formData.append('template', file);
        
        fetch('api/pod-admin.php', {
            method: 'POST',
            body: formData
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                showDesignTemplatePreview(data.template_url);
            } else {
                alert(data.error || 'Failed to upload design template');
            }
        })
        .catch(err => {
            console.error('Design template upload error:', err);
            alert('Failed to upload design template. Please try again.');
        });
    }
    
    function showDesignTemplatePreview(url) {
        document.getElementById('designTemplatePreviewImg').src = url;
        document.getElementById('currentDesignTemplatePreview').style.display = 'block';
    }
    
    function hideDesignTemplatePreview() {
        document.getElementById('currentDesignTemplatePreview').style.display = 'none';
        document.getElementById('designTemplatePreviewImg').src = '';
    }
    
    function removeDesignTemplate() {
        if (!confirm('Remove design template? Customers will not be able to customize this product.')) return;
        
        const productId = document.getElementById('editProductId').value;
        const formData = new FormData();
        formData.append('action', 'remove_design_template');
        formData.append('id', productId);
        
        fetch('api/pod-admin.php', {
            method: 'POST',
            body: formData
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                hideDesignTemplatePreview();
            } else {
                alert('Failed to remove design template');
            }
        })
        .catch(err => {
            console.error('Remove design template error:', err);
            alert('Failed to remove design template. Please try again.');
        });
    }
    
    // 360 preview toggle
    document.addEventListener('DOMContentLoaded', function() {
        const enable360Checkbox = document.getElementById('editEnable360');
        if (enable360Checkbox) {
            enable360Checkbox.addEventListener('change', function() {
                const measurementsSection = document.getElementById('edit3DMeasurementsSection');
                if (measurementsSection) {
                    measurementsSection.style.display = this.checked ? 'block' : 'none';
                }
            });
        }
    });
    
    // Product shape selection
    let currentProductShape = 'flat';
    
    function selectProductShape(shape) {
        currentProductShape = shape;
        const flatLabel = document.getElementById('shapeFlat');
        const roundLabel = document.getElementById('shapeRound');
        const enable360Container = document.getElementById('enable360Container');
        const measurementsSection = document.getElementById('edit3DMeasurementsSection');
        const enable360Checkbox = document.getElementById('editEnable360');
        
        if (shape === 'round') {
            flatLabel.classList.remove('shape-selected');
            roundLabel.classList.add('shape-selected');
            flatLabel.querySelector('input').checked = false;
            roundLabel.querySelector('input').checked = true;
            if (enable360Container) enable360Container.style.display = 'block';
            if (measurementsSection && enable360Checkbox && enable360Checkbox.checked) {
                measurementsSection.style.display = 'block';
            }
        } else {
            flatLabel.classList.add('shape-selected');
            roundLabel.classList.remove('shape-selected');
            flatLabel.querySelector('input').checked = true;
            roundLabel.querySelector('input').checked = false;
            if (enable360Container) enable360Container.style.display = 'none';
            if (measurementsSection) measurementsSection.style.display = 'none';
            if (enable360Checkbox) enable360Checkbox.checked = false;
        }
    }
    
    // Populate customization fields when editing
    function populateCustomizationFields(product) {
        const section = document.getElementById('customizationSettingsSection');
        if (!section) return;
        
        // Show/hide section based on customizable status
        section.style.display = product.is_customizable ? 'block' : 'none';
        
        // Design template
        if (product.template_url) {
            showDesignTemplatePreview(product.template_url.startsWith('/') ? product.template_url : '/' + product.template_url);
        } else {
            hideDesignTemplatePreview();
        }
        
        // Template dimensions
        document.getElementById('editCanvasWidth').value = product.canvas_width || 500;
        document.getElementById('editCanvasHeight').value = product.canvas_height || 600;
        document.getElementById('editTargetX').value = product.target_x || 50;
        document.getElementById('editTargetY').value = product.target_y || 50;
        document.getElementById('editTargetWidth').value = product.target_width || 400;
        document.getElementById('editTargetHeight').value = product.target_height || 500;
        
        // Mockup placement
        document.getElementById('editMockupX').value = product.mockup_x || 25;
        document.getElementById('editMockupY').value = product.mockup_y || 15;
        document.getElementById('editMockupWidth').value = product.mockup_width || 50;
        document.getElementById('editMockupHeight').value = product.mockup_height || 70;
        
        // Feed text and styling
        document.getElementById('editFeedText').value = product.custom_feed_text || '';
        document.getElementById('editFeedTextFont').value = product.feed_text_font || 'inherit';
        document.getElementById('editFeedTextSize').value = product.feed_text_size || '18px';
        const colorValue = product.feed_text_color || '#1c1e21';
        document.getElementById('editFeedTextColor').value = colorValue;
        document.getElementById('editFeedTextColorHex').value = colorValue;
        document.getElementById('editFeedTextWeight').value = product.feed_text_weight || '700';
        updateFeedTextPreview();
        
        // Product shape
        const shape = product.product_shape || 'flat';
        selectProductShape(shape);
        
        // Swap size/color
        document.getElementById('editSwapSizeColor').checked = !!product.swap_size_color;
        
        // 360 preview
        const enable360 = document.getElementById('editEnable360');
        enable360.checked = !!product.enable_360_preview;
        if (shape === 'round') {
            document.getElementById('edit3DMeasurementsSection').style.display = enable360.checked ? 'block' : 'none';
        }
        
        // 3D measurements
        document.getElementById('editProductHeight').value = product.product_height || '';
        document.getElementById('editTopDiameter').value = product.top_diameter || '';
        document.getElementById('editBottomDiameter').value = product.bottom_diameter || '';
        document.getElementById('editPrintAreaWidth').value = product.print_area_width || '';
        document.getElementById('editPrintAreaHeight').value = product.print_area_height || '';
        document.getElementById('editPrintTopOffset').value = product.print_area_top_offset || '';
    }
    
    // Save customization settings (called from saveProductEdit)
    function getCustomizationSettings() {
        return {
            canvas_width: parseInt(document.getElementById('editCanvasWidth').value) || 500,
            canvas_height: parseInt(document.getElementById('editCanvasHeight').value) || 600,
            target_x: parseInt(document.getElementById('editTargetX').value) || 50,
            target_y: parseInt(document.getElementById('editTargetY').value) || 50,
            target_width: parseInt(document.getElementById('editTargetWidth').value) || 400,
            target_height: parseInt(document.getElementById('editTargetHeight').value) || 500,
            mockup_x: parseInt(document.getElementById('editMockupX').value) || 25,
            mockup_y: parseInt(document.getElementById('editMockupY').value) || 15,
            mockup_width: parseInt(document.getElementById('editMockupWidth').value) || 50,
            mockup_height: parseInt(document.getElementById('editMockupHeight').value) || 70,
            custom_feed_text: document.getElementById('editFeedText').value || '',
            feed_text_font: document.getElementById('editFeedTextFont').value || 'inherit',
            feed_text_size: document.getElementById('editFeedTextSize').value || '18px',
            feed_text_color: document.getElementById('editFeedTextColor').value || '#1c1e21',
            feed_text_weight: document.getElementById('editFeedTextWeight').value || '700',
            product_shape: currentProductShape,
            swap_size_color: document.getElementById('editSwapSizeColor').checked,
            enable_360_preview: document.getElementById('editEnable360').checked,
            product_height: parseFloat(document.getElementById('editProductHeight').value) || null,
            top_diameter: parseFloat(document.getElementById('editTopDiameter').value) || null,
            bottom_diameter: parseFloat(document.getElementById('editBottomDiameter').value) || null,
            print_area_width: parseFloat(document.getElementById('editPrintAreaWidth').value) || null,
            print_area_height: parseFloat(document.getElementById('editPrintAreaHeight').value) || null,
            print_area_top_offset: parseFloat(document.getElementById('editPrintTopOffset').value) || null
        };
    }
    </script>
</body>
</html>
