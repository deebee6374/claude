<?php
declare(strict_types=1);

$sites = [
    'smooch' => ['dir' => 'smoochwebsite', 'label' => 'Smooch', 'view' => 'smoochwebsite/view.php'],
    'kiss'   => ['dir' => 'kiss',          'label' => 'Kiss',   'view' => 'kiss/view.php'],
];

$currentSite = isset($_GET['site'], $sites[$_GET['site']]) ? $_GET['site'] : 'smooch';
$siteDir     = $sites[$currentSite]['dir'];
$dataFile    = $siteDir . '/data.json';

function loadEntries(string $file): array {
    if (!file_exists($file)) return [];
    $data = json_decode(file_get_contents($file), true);
    return is_array($data) ? $data : [];
}

function saveEntries(string $file, array $entries): void {
    file_put_contents($file, json_encode($entries, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

function sortNewestFirst(array $entries): array {
    usort($entries, fn($a, $b) => strcmp($b['date'], $a['date']));
    return $entries;
}

// Handle delete
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['delete'], $_GET['site'])) {
    $site = $_GET['site'];
    if (isset($sites[$site])) {
        $file    = $sites[$site]['dir'] . '/data.json';
        $entries = loadEntries($file);
        $entries = array_values(array_filter($entries, fn($e) => $e['id'] !== $_GET['delete']));
        saveEntries($file, $entries);
    }
    header('Location: memorial-admin.php?site=' . $currentSite . '&deleted=1');
    exit;
}

// Handle add
$errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $site   = $_POST['site'] ?? '';
    $column = in_array($_POST['column'] ?? '', ['left', 'right']) ? $_POST['column'] : 'left';
    $date   = trim($_POST['date'] ?? '');
    $text   = trim($_POST['text'] ?? '');
    $youtube = trim($_POST['youtube'] ?? '');

    if (!isset($sites[$site]))   $errors[] = 'Invalid site.';
    if ($date === '')            $errors[] = 'Date is required.';
    if ($text === '' && $youtube === '' && empty($_FILES['image']['name'])) {
        $errors[] = 'Please provide text, an image, or a YouTube URL.';
    }

    if (empty($errors)) {
        $dir   = $sites[$site]['dir'];
        $entry = [
            'id'         => uniqid('', true),
            'date'       => $date,
            'column'     => $column,
            'text'       => $text,
            'youtube'    => $youtube,
            'image'      => '',
            'created_at' => date('Y-m-d H:i:s'),
        ];

        if (!empty($_FILES['image']['name']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
            $allowed = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
            $ext     = strtolower(pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION));
            if (!in_array($ext, $allowed)) {
                $errors[] = 'Image must be jpg, png, gif, or webp.';
            } else {
                $uploadDir = $dir . '/uploads/';
                if (!is_dir($uploadDir)) mkdir($uploadDir, 0755, true);
                $filename = uniqid('img_', true) . '.' . $ext;
                if (move_uploaded_file($_FILES['image']['tmp_name'], $uploadDir . $filename)) {
                    $entry['image'] = 'uploads/' . $filename;
                } else {
                    $errors[] = 'Image upload failed.';
                }
            }
        }

        if (empty($errors)) {
            $file    = $dir . '/data.json';
            $entries = loadEntries($file);
            $entries[] = $entry;
            saveEntries($file, $entries);
            header('Location: memorial-admin.php?site=' . $site . '&saved=1');
            exit;
        }
    }
    $currentSite = $site;
    $siteDir     = $sites[$currentSite]['dir'];
    $dataFile    = $siteDir . '/data.json';
}

$entries = sortNewestFirst(loadEntries($dataFile));
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Memorial Pages Admin</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: Arial, sans-serif; background: #1a1a1a; color: #e0e0e0; min-height: 100vh; }

  .header { background: #111; border-bottom: 2px solid #3C599B; padding: 16px 24px; display: flex; align-items: center; gap: 16px; }
  .header h1 { font-size: 1.3rem; color: #FFFF00; }
  .tabs { display: flex; gap: 8px; margin-left: auto; }
  .tab { padding: 8px 20px; border-radius: 4px; text-decoration: none; font-size: 0.9rem; font-weight: bold; border: 2px solid #3C599B; color: #ccc; }
  .tab.active { background: #3C599B; color: #fff; }

  .layout { display: grid; grid-template-columns: 380px 1fr; gap: 24px; padding: 24px; max-width: 1200px; margin: 0 auto; }

  @media (max-width: 720px) { .layout { grid-template-columns: 1fr; } }

  .card { background: #242424; border: 1px solid #333; border-radius: 8px; padding: 20px; }
  .card h2 { font-size: 1rem; color: #FFFF00; margin-bottom: 16px; border-bottom: 1px solid #333; padding-bottom: 8px; }

  label { display: block; font-size: 0.85rem; color: #aaa; margin-bottom: 4px; margin-top: 14px; }
  input[type=text], input[type=date], textarea {
    width: 100%; padding: 8px 10px; background: #1a1a1a; border: 1px solid #444;
    color: #e0e0e0; border-radius: 4px; font-size: 0.9rem;
  }
  textarea { resize: vertical; min-height: 110px; }
  input[type=file] { color: #aaa; font-size: 0.85rem; margin-top: 4px; }

  .col-select { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 4px; }
  .col-btn { padding: 10px; text-align: center; border: 2px solid #444; border-radius: 6px;
             cursor: pointer; font-size: 0.85rem; color: #aaa; user-select: none; }
  .col-btn input { display: none; }
  .col-btn.selected { border-color: #3C599B; background: #1e2a3a; color: #fff; }

  .btn-submit { margin-top: 18px; width: 100%; padding: 11px; background: #3C599B; color: #fff;
                border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; font-weight: bold; }
  .btn-submit:hover { background: #2d4578; }

  .alert { padding: 10px 14px; border-radius: 4px; margin-bottom: 16px; font-size: 0.9rem; }
  .alert-success { background: #1a3a1a; border: 1px solid #2d6a2d; color: #7dcc7d; }
  .alert-error   { background: #3a1a1a; border: 1px solid #6a2d2d; color: #cc7d7d; }

  .entries-list { display: flex; flex-direction: column; gap: 12px; }
  .entry { background: #1a1a1a; border: 1px solid #333; border-radius: 6px; padding: 14px; position: relative; }
  .entry-meta { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }
  .entry-date { font-weight: bold; color: #FFFF00; font-size: 0.9rem; }
  .entry-col  { font-size: 0.75rem; padding: 2px 8px; border-radius: 10px; font-weight: bold; }
  .entry-col.left  { background: #1e3a2a; color: #7dcc9d; border: 1px solid #2d6a4d; }
  .entry-col.right { background: #1e2a3a; color: #7daacc; border: 1px solid #2d4a6a; }
  .entry-text { font-size: 0.85rem; color: #bbb; white-space: pre-wrap; word-break: break-word; }
  .entry-youtube { font-size: 0.8rem; color: #7daacc; margin-top: 6px; word-break: break-all; }
  .entry-image { display: block; margin-top: 8px; max-width: 200px; max-height: 130px; border-radius: 4px; border: 1px solid #444; object-fit: cover; }
  .entry-actions { position: absolute; top: 12px; right: 12px; }
  .btn-delete { background: #5a1a1a; border: 1px solid #8a2a2a; color: #cc7d7d;
                padding: 4px 10px; border-radius: 4px; font-size: 0.75rem; text-decoration: none; }
  .btn-delete:hover { background: #7a2a2a; }

  .view-link { display: inline-block; margin-bottom: 16px; padding: 6px 14px;
               background: #222; border: 1px solid #3C599B; color: #7daaff;
               border-radius: 4px; text-decoration: none; font-size: 0.85rem; }
  .view-link:hover { background: #1e2a3a; }
  .empty { color: #555; font-size: 0.9rem; text-align: center; padding: 30px; }
  .count { font-size: 0.8rem; color: #666; margin-left: 6px; }
</style>
</head>
<body>

<div class="header">
  <h1>Memorial Pages Admin</h1>
  <div class="tabs">
    <?php foreach ($sites as $key => $info): ?>
      <a href="memorial-admin.php?site=<?= $key ?>" class="tab <?= $currentSite === $key ? 'active' : '' ?>">
        <?= $info['label'] ?>
      </a>
    <?php endforeach; ?>
  </div>
</div>

<div class="layout">

  <div class="card">
    <h2>Add Entry &mdash; <?= $sites[$currentSite]['label'] ?></h2>

    <?php if (!empty($errors)): ?>
      <div class="alert alert-error"><?= implode('<br>', array_map('htmlspecialchars', $errors)) ?></div>
    <?php endif; ?>

    <form method="POST" enctype="multipart/form-data">
      <input type="hidden" name="site" value="<?= $currentSite ?>">

      <label for="date">Date *</label>
      <input type="date" id="date" name="date"
             value="<?= htmlspecialchars($_POST['date'] ?? date('Y-m-d')) ?>" required>

      <label>Column *</label>
      <div class="col-select">
        <label class="col-btn <?= ($_POST['column'] ?? 'left') === 'left' ? 'selected' : '' ?>">
          <input type="radio" name="column" value="left"
                 <?= ($_POST['column'] ?? 'left') === 'left' ? 'checked' : '' ?>>
          &#9664; Left Column
        </label>
        <label class="col-btn <?= ($_POST['column'] ?? '') === 'right' ? 'selected' : '' ?>">
          <input type="radio" name="column" value="right"
                 <?= ($_POST['column'] ?? '') === 'right' ? 'checked' : '' ?>>
          Right Column &#9654;
        </label>
      </div>

      <label for="text">Text / Message</label>
      <textarea id="text" name="text"
                placeholder="Write your message here..."><?= htmlspecialchars($_POST['text'] ?? '') ?></textarea>

      <label for="image">Image Upload</label>
      <input type="file" id="image" name="image" accept="image/jpeg,image/png,image/gif,image/webp">

      <label for="youtube">YouTube URL</label>
      <input type="text" id="youtube" name="youtube"
             placeholder="https://www.youtube.com/watch?v=..."
             value="<?= htmlspecialchars($_POST['youtube'] ?? '') ?>">

      <button type="submit" class="btn-submit">+ Add Entry</button>
    </form>
  </div>

  <div class="card">
    <h2>
      Entries &mdash; Newest First
      <span class="count">(<?= count($entries) ?> total)</span>
    </h2>

    <?php if (isset($_GET['saved'])): ?>
      <div class="alert alert-success">Entry saved successfully.</div>
    <?php endif; ?>
    <?php if (isset($_GET['deleted'])): ?>
      <div class="alert alert-success">Entry deleted.</div>
    <?php endif; ?>

    <a href="<?= $sites[$currentSite]['view'] ?>" target="_blank" class="view-link">
      View <?= $sites[$currentSite]['label'] ?> Page &rarr;
    </a>

    <?php if (empty($entries)): ?>
      <p class="empty">No entries yet. Add one using the form.</p>
    <?php else: ?>
      <div class="entries-list">
        <?php foreach ($entries as $entry): ?>
          <div class="entry">
            <div class="entry-meta">
              <span class="entry-date"><?= htmlspecialchars(date('F j, Y', strtotime($entry['date']))) ?></span>
              <span class="entry-col <?= htmlspecialchars($entry['column']) ?>">
                <?= $entry['column'] === 'left' ? '&#9664; Left' : 'Right &#9654;' ?>
              </span>
            </div>
            <?php if ($entry['text']): ?>
              <div class="entry-text"><?= htmlspecialchars($entry['text']) ?></div>
            <?php endif; ?>
            <?php if ($entry['image']): ?>
              <img class="entry-image"
                   src="<?= htmlspecialchars($siteDir . '/' . $entry['image']) ?>"
                   alt="Entry image">
            <?php endif; ?>
            <?php if ($entry['youtube']): ?>
              <div class="entry-youtube">&#9654; <?= htmlspecialchars($entry['youtube']) ?></div>
            <?php endif; ?>
            <div class="entry-actions">
              <a class="btn-delete"
                 href="memorial-admin.php?site=<?= $currentSite ?>&delete=<?= urlencode($entry['id']) ?>"
                 onclick="return confirm('Delete this entry?')">Delete</a>
            </div>
          </div>
        <?php endforeach; ?>
      </div>
    <?php endif; ?>
  </div>

</div>

<script>
  document.querySelectorAll('input[name="column"]').forEach(radio => {
    radio.addEventListener('change', () => {
      document.querySelectorAll('.col-btn').forEach(b => b.classList.remove('selected'));
      radio.closest('.col-btn').classList.add('selected');
    });
  });
</script>
</body>
</html>
