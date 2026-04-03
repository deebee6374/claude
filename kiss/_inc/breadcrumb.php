<?php
	

function bcIndex($dir) {
	$index = '';
	@$dir_handle = opendir($dir);
	if ($dir_handle) {
		while ($file = readdir($dir_handle)) {
			$test = substr(strtolower($file), 0, 6);
			if ($test == 'index.') {
				$index = $file;
				break;
				}
			}
		}
	return $index;
	}
function bcArray($array) {
	$clean = array();
	for ($n=0; $n<count($array); $n++) {
		$entry = trim($array[$n]);
		if ($entry != '') $clean[] = $entry;
		}
	return $clean;
	}
function bcNames($string) {
	global $convert_toSpace;
	global $upperCaseWords;
	if ($convert_toSpace) $string = str_replace('_', ' ', $string);
	if ($upperCaseWords) $string = ucwords($string);
	return $string;
	}
$server = (isset($_SERVER)) ? $_SERVER : $HTTP_SERVER_VARS;
$htmlRoot = (isset($server['DOCUMENT_ROOT'])) ? $server['DOCUMENT_ROOT'] : '';
if ($htmlRoot == '') $htmlRoot = (isset($server['SITE_HTMLROOT'])) ? $server['SITE_HTMLROOT'] : '';
$pagePath = (isset($server['SCRIPT_FILENAME'])) ? $server['SCRIPT_FILENAME'] : '';
if ($pagePath == '') $pagePath = (isset($server['SCRIPT_FILENAME'])) ? $server['SCRIPT_FILENAME'] : '';
$httpPath = ($htmlRoot != '/') ? str_replace($htmlRoot, '', $pagePath) : $pathPath;
$dirArray = explode('/', $httpPath);
if (!is_dir($htmlRoot.$httpPath)) $dirArray = array_slice($dirArray, 0, count($dirArray) - 1);
$linkArray = array();
$thisDir = '';
$baseDir = ($htmlRoot == '') ? '' : $htmlRoot;
for ($n=0; $n<count($dirArray); $n++) {
	$thisDir .= $dirArray[$n].'/';
	$thisIndex = bcIndex($htmlRoot.$thisDir);
	$thisText = ($n == 0) ? $topLevelName : bcNames($dirArray[$n]);
	$thisLink = ($thisIndex != '') ? '<a href="'.$thisDir.$thisIndex.'">'.$thisText.'</a>' : $thisText;
	if ($thisLink != '') $linkArray[] = $thisLink;
	}
$results = (count($linkArray) > 0) ? implode($separator, $linkArray) : '';
if ($results != '') print($results);
?>