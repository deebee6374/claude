<?php
$dataFile = __DIR__ . '/data.json';
$entries  = [];
if (file_exists($dataFile)) {
    $data    = json_decode(file_get_contents($dataFile), true);
    $entries = is_array($data) ? $data : [];
    usort($entries, fn($a, $b) => strcmp($b['date'], $a['date']));
}
$leftEntries  = array_filter($entries, fn($e) => $e['column'] === 'left');
$rightEntries = array_filter($entries, fn($e) => $e['column'] === 'right');

function youtubeEmbed(string $url): string {
    preg_match('/(?:v=|youtu\.be\/)([a-zA-Z0-9_-]{11})/', $url, $m);
    if (!isset($m[1])) return '';
    $id = htmlspecialchars($m[1]);
    return '<iframe width="560" height="315" src="https://www.youtube.com/embed/' . $id . '"
            title="YouTube video player" frameborder="0"
            allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
            allowfullscreen></iframe>';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Our Darling Smooch</title>
<style>
a:link, a:visited { background-color: #3C599B; color: white; padding: 6px; text-align: center; text-decoration: none; display: inline-block; }
a:hover, a:active { background-color: darkcyan; }
.entry-date { color: #FFFF00; font-weight: bold; }
.entry-text { color: #ffffff; white-space: pre-wrap; }
</style>
</head>
<body bgcolor="#000000">
<table align="center" border="2" cellpadding="10" cellspacing="1" width="95%">
  <tbody>
    <!-- Static top row: portrait and tribute -->
    <tr>
      <td valign="top">
        <p><font color="#FFFF00" size="+3">Smooch</font></p>
        <p align="center"><img src="Smooch_Portrait.JPG" width="350" alt="Smooch" /></p>
      </td>
      <td width="65%" valign="middle">
        <font color="#FFFFFF">
          I was Smooch. Daddy's little puppy, protector, mind reader.<br /><br />
          I received over 13 years of love and care. Mommy tried to helped me stay as long as she could without pain.<br /><br />
          But, it was my time to go join Tiger. I will miss my family. I know they will miss me too.<br />
          <img alt="The Eternal Flame." src="Flame2.gif" style="border-width:0;border-style:solid;" /><br /><br />
          This is an eternal flame which burns for me forever, as my beloved owners mourn and remember me forever.<br />
          I hope they remember the good times we had and always know how much they meant to me.
        </font>
      </td>
    </tr>

    <!-- Dynamic entries row -->
    <tr>
      <!-- Left column -->
      <td valign="top">
        <?php foreach ($leftEntries as $entry): ?>
          <p><font color="#FFFF00"><?= htmlspecialchars(date('F j, Y', strtotime($entry['date']))) ?></font></p>
          <?php if ($entry['text']): ?>
            <p><font color="#FFFFFF"><?= nl2br(htmlspecialchars($entry['text'])) ?></font></p>
          <?php endif; ?>
          <?php if ($entry['image']): ?>
            <p><img src="<?= htmlspecialchars($entry['image']) ?>" width="100%" alt="" /></p>
          <?php endif; ?>
          <?php if ($entry['youtube']): ?>
            <p><?= youtubeEmbed($entry['youtube']) ?></p>
          <?php endif; ?>
        <?php endforeach; ?>
      </td>

      <!-- Right column -->
      <td valign="top">
        <p><img alt="Smooch" src="cloud.jpg" width="40%" /></p>
        <?php foreach ($rightEntries as $entry): ?>
          <p><font color="#FFFF00"><?= htmlspecialchars(date('F j, Y', strtotime($entry['date']))) ?></font></p>
          <?php if ($entry['text']): ?>
            <p><font color="#FFFFFF"><?= nl2br(htmlspecialchars($entry['text'])) ?></font></p>
          <?php endif; ?>
          <?php if ($entry['image']): ?>
            <p><img src="<?= htmlspecialchars($entry['image']) ?>" width="100%" alt="" /></p>
          <?php endif; ?>
          <?php if ($entry['youtube']): ?>
            <p><?= youtubeEmbed($entry['youtube']) ?></p>
          <?php endif; ?>
        <?php endforeach; ?>
      </td>
    </tr>
  </tbody>
</table>
</body>
</html>
