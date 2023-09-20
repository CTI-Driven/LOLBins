
function opentag(evt, Name) {
  var i, tabcontent, tablinks;
  tabcontent = document.getElementsByClassName("tabcontent");
  for (i = 0; i < tabcontent.length; i++) {
    tabcontent[i].style.display = "none";
  }
  tablinks = document.getElementsByClassName("tablinks");
  for (i = 0; i < tablinks.length; i++) {
    tablinks[i].className = tablinks[i].className.replace(" active", "");
  }
  document.getElementById(Name).style.display = "block";
  evt.currentTarget.className += " active";
}

function opentagn(evt, Name) {
  var i, tabcontentn, tablinksn;
  tabcontentn = document.getElementsByClassName("tabcontentn");
  for (i = 0; i < tabcontentn.length; i++) {
    tabcontentn[i].style.display = "none";
  }
  tablinksn = document.getElementsByClassName("tablinksn");
  for (i = 0; i < tablinksn.length; i++) {
    tablinksn[i].className = tablinksn[i].className.replace(" active", "");
  }
  document.getElementById(Name).style.display = "block";
  evt.currentTarget.className += " active";
  
}
