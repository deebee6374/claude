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
<title>Our Darling Kiss</title>
<style>
a:link, a:visited { background-color: #3C599B; color: white; padding: 6px; text-align: center; text-decoration: none; display: inline-block; }
a:hover, a:active { background-color: darkcyan; }
</style>
</head>
<body bgcolor="#000000">
<table align="center" border="2" cellpadding="10" cellspacing="1" width="95%">
  <tbody>
    <!-- Static top row: portrait and tribute -->
    <tr>
      <td width="35%" valign="top">
        <p><font color="#FFFF00" size="+3">Kiss</font></p>
        <p><img height="235" src="http://www.deniseboubour.com/full.jpg" width="176" alt="Kiss" /></p>
      </td>
      <td width="65%" valign="middle">
        <font color="#FFFFFF">
          I was Kiss, the sweetest cat ever! I loved Jack and Denise with all my heart. I gave them unending love and devotion every day of my short life.<br /><br />
          I lived to play with them everyday, and give them a little Kiss on the lips. That's how I got my name. I miss them so much, and I know they miss me too. Maybe someday we'll be together again.<br /><br />
          <img alt="The Eternal Flame." src="Flame2.gif" style="border-width:0;border-style:solid;" /><br /><br />
          This is an eternal flame which burns for me forever, as my beloved owners mourn and remember me forever.
        </font>
      </td>
    </tr>

    <!-- Dynamic entries row -->
    <tr>
      <!-- Left column -->
      <td valign="top">
        <p><font color="#FFFFFF"><img src="tombstone.gif" alt="Tombstone" /><br /><br />
        Kiss...we had no grave sadly. So, this is a symbolic stone. It is made with all our love.</font></p>

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
