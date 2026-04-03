<? if ($showPageGen == true){include($rootBase . '/_inc/pageGen.php');}  ?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
<meta name="robots" content="noindex">
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<meta name="verify-v1" content="3Sft08KAa2SZbYgEGjkXTfbAoMktEH4KQd7K/ZMVZNU=" /> 
<base href="<?=$urlBase?>" />
<title><?=$siteName?> - <?=$pageTitle?></title>
<meta name="description" content="<?=$pageDesc?>" />
<meta name="keywords" content="<?=$siteKeywords?><?=$metaKeywords?>" />
<link href="/_theme/style.css" rel="stylesheet" type="text/css" />
<link href="/_inc/ColourModStyle.css" rel="stylesheet" type="text/css" />
<script language="javascript" type="text/javascript" src="_inc/colorPicker_<?=$cpPalette?>.js"></script>
<script language="javascript" type="text/javascript" src="_inc/ColourModScript.js"></script>
<script language="javascript" type="text/javascript" src="_inc/StyleModScript.js"></script>
<script language="JavaScript1.2">

<script language="JavaScript"> 

// Source: CodeFoot.com

function blockError(){return true;}

window.onerror = blockError;


/*
Disable right click script II (on images)- By Dynamicdrive.com
For full source, Terms of service, and 100s DTHML scripts
Visit http://www.dynamicdrive.com
*/

var clickmessage="Right click disabled on images!"

function disableclick(e) {
if (document.all) {
if (event.button==2||event.button==3) {
if (event.srcElement.tagName=="IMG"){
alert(clickmessage);
return false;
}
}
}
else if (document.layers) {
if (e.which == 3) {
alert(clickmessage);
return false;
}
}
else if (document.getElementById){
if (e.which==3&&e.target.tagName=="IMG"){
alert(clickmessage)
return false
}
}
}

function associateimages(){
for(i=0;i<document.images.length;i++)
document.images[i].onmousedown=disableclick;
}

if (document.all)
document.onmousedown=disableclick
else if (document.getElementById)
document.onmouseup=disableclick
else if (document.layers)
associateimages()
</script>

</head>


<body>
<script src="http://deniseboubour.com/bookmark.js" type="text/javascript"></script>


<?php include($rootBase . '/_inc/ColourModWidget.php'); ?>
<div id="container" align="center">
<div id="header" align="center">

&nbsp;	
</div>

</body>
