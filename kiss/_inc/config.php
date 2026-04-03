<?php




### Site Variables
/*******************************************************************************************/

// Email where you will recieve messages (i.e. ad requests)
$adminEmail = "dboubour@yahoo.com"; 

// Example: Website.com
$siteName = "deniseboubour.com"; 

// Default title
$defaultTitle = "Denise Boubour - Marketing Professional"; 

// Default description
$defaultDescription = "Denise Boubour professional resume and sample work products."; 

// meta keywords that appear in every page
$siteKeywords ="marketing, ecommerce, website, seo, cpm"; 

// URL of the folder this site is located 
$urlBase = "http://www.deniseboubour.com"; 

//SHORT snippet of text to display in code. example: More images at MyspaceScriptz
$linkBack = "Denise Boubour"; 

// Insert the code that goes into the copy/paste box that displays your linkTag on their myspace prfile (default = true)
$showLinkTag = true;

// the tag line in the alt tags of images
$imgAlt = "deniseboubour.com"; 

// Number of Images shown per page
$imageListImageCount = 11;
$imageListFlashCount = 11;

// Number of Thumbnails shown per page
$thumbListImageCount = 14;

// Display 'page generated in' time? (true or false)
$showPageGen = true;

// Link to image upload site (leave as http://www.myspaceimagez.com if unsure)
$link2ImageSite = "http://www.deniseboubour.com/";

// Color Pallette to use for colorPicker
	// use 'PS' for a photoshop color swatch (smallest / cleanest)
	// use 'DW' for the dreamweaver web-safe color picker (all web-safe colors)
	// use 'SH' for the ScriptHippo color table (most detailed / prettiest)
$cpPalette = 'SH';



### Breadcrumb Settings
/*******************************************************************************************/

// convert _ in folder names to spaces
$convert_toSpace = true;	

// convert lowercase to initial caps
$upperCaseWords = true;	

// name of home/root directory
$topLevelName = "deniseboubour.com";

// link seperator
$separator = " &raquo; ";




### ONLY EDIT BELOW THIS LINE IF YOU HAVE A GOOD REASON
/*******************************************************************************************/
// Current http url
	$url2here = $urlBase . $_SERVER['REQUEST_URI'];
	$url2folder = substr($url2here, 0, strrpos($url2here, "/")) . "/";
	


// Back Button
	$backButton = '<br /><br /><span class="backButton"><a href="' . $url2folder . '">&lt;&lt; back</a></span><br /><br />';

?>