//more or less equivalent of PHP's htmlspecialchars()
function htmlspecialchars(string){ return jQuery('<span>').text(string).html(); }

jQuery(document).ready(function(){

	//toggle detailed display
	jQuery("li.looksee-status-bad").click(function(){
		var obj = jQuery(".looksee-status-details-" + jQuery(this).attr('data-scan'));
		if(obj.css('display') == 'none')
			obj.css('display','block');
		else
			obj.css('display','none');
	});

	//elaborate on what settings do
	jQuery(".settings-help").click(function(e){
		e.preventDefault();
		var title = jQuery(this).attr('data-help');
		if(title.length)
			alert(title);
	});

});