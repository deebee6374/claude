function bookmark(title, url){
if (document.all)
window.external.AddFavorite(url, title);
else if (window.sidebar)
window.sidebar.addPanel(title, url, "")
}

function bookmark(){
var title = 'Commentbaby';
var url = 'http://commentbaby.com';
   if (document.all)
     window.external.AddFavorite(url, title);
   else if (window.sidebar)
     window.sidebar.addPanel(title, url, "")
   else if (window.sidebar&&window.sidebar.addPanel)
     window.sidebar.addPanel(title,url,"");
}

