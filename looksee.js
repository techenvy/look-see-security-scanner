var looksee = null;

(function($){
	looksee = {

		//------------------------------------------------------------------------
		// Some initializations that need to run when the doc is ready
		//------------------------------------------------------------------------

		init: function() {

		},



		//------------------------------------------------------------------------
		// Functions triggered by user action (e.g. click)
		//------------------------------------------------------------------------

		interactive: function() {

			//toggle detailed display
			$('body').on('click', "li.looksee-status-bad", function(){
				var obj = $(".looksee-status-details-" + $(this).attr('data-scan'));
				if(obj.css('display') == 'none')
					obj.css('display','block');
				else
					obj.css('display','none');
			});

			//elaborate on what settings do
			$('body').on('click', ".settings-help", function(e){
				e.preventDefault();
				var title = $(this).attr('data-help');
				if(title.length)
					alert(title);
			});

		},

		//------------------------------------------------------------------------ end interactive



		//------------------------------------------------------------------------
		// Custom functions
		//------------------------------------------------------------------------

		//-------------------------------------------------
		// MISC DATA HELPERS

		//test whether object is json
		isJSON: function(value) {
			try {
				JSON.stringify(value);
				return true;
			}
			catch (ex) {
				return false;
			}
		}

		//------------------------------------------------------------------------ end custom functions
	};

	//call some stuff when the document is ready
	$(document).ready(function(){

		//bind interactive events
		looksee.interactive();

		//initialize
		looksee.init();

	});

})(jQuery);