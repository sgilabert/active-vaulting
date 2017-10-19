var sessionCheck = function (sessionCheckURL, loginURL, interval) {
    var interval = setInterval(function(){
        $.ajax({
            url : sessionCheckURL,
            type : 'GET',
            global : false,
            success : function (data) {
                // If session expired redirect to login page
                if(data.is_expired){
                    window.location = loginURL;
                }
            },
        });
    }, interval);

    return interval;

};

sessionCheckInterval = sessionCheck('/sessioncheck/' /* sessionCheckURL */, '/' /* loginURL */, 5000 /* interval */);
