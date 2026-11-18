/**
 * Upload Files Directly
 *
 *
 * Worked for:
 *    <form class="direct-upload"> <input type="file">
 *
 *
 * [Optional]
 *    <input type="file" data-callback="callbackFunc">
 *
 *    window.callbackFunc ( array messages : statuses uploaded file[s] )
 */

;(document.addEventListener ( "DOMContentLoaded", function ()
{
    var current = null;
    var files = {};

    var _upld = function ( url, file )
    {
        var reader = new FileReader();

        reader.onload = function ( e )
        {
            fetch ( url,
            {
                method : 'POST',
                headers : {
                    'Content-Type' : file.type || 'application/octet-stream',
                    'X-File-Upload': encodeURIComponent ( current.name ),
                    'X-File-Name'  : encodeURIComponent ( file.name ),
                    'Content-Length' : reader.result.length
                },
                body: reader.result
            })
            .then ( response => (response.status==200)&&response.json() )
            .then ( data => _clb ( file, data, null ) )
            .catch( error => _clb ( file, null, error ) )
            ;
        };
        reader.onerror = function ( e )
        {
            console.log( 'error upload', reader.error );
            _clb ( file, null, reader.error )
        };

        reader.readAsArrayBuffer( file );
    };

    var _clb = function ( file, data, error )
    {
        files.count++;

        var mess = [ 'Uploaded Files:' ];
        for ( var k = 0; k < files.length; k++ )
        {
            if ( files[k].name == file.name )
            {
                files[k].result = file.name + ' : ' + ( error ? 'ERROR: ' + error : ( data.success ? 'OK': (data.error||'Not Success') ) );
            }
            mess.push ( files[k].result );
        }

        if ( files.count >= files.length )
        {
            current.disabled = false;
            current.value = '';

            var clb = current.getAttribute('data-callback');

            current = null;
            files = {};

            if ( clb && typeof window[ clb ] == 'function' )
            {
                window[ clb ] ( mess );
            }
            else
            {
                alert ( mess.join("\n") );
            }
        }
    };

    var _chng = function ( e )
    {
        var t = e.target;

        if ( ! t.files.length || current )
        {
            t.value = '';
            return;
        }

        t.disabled = true;
        var url = t.closest('form').action;

        current = t;
        files = t.files;
        files.count = 0;

        for ( var k = 0; k < files.length; k++ )
        {
            _upld ( url, t.files[k], _clb );
        }
    };

    document.querySelectorAll('form').forEach( function ( frm )
    {
        if (
            ! frm.classList.contains('direct-upload')
            ||
            ! document.querySelectorAll('input[type="file"]', frm).length
        ) {
            return;
        }

        document.querySelectorAll('input[type="file"]', frm).forEach( function ( fl )
        {
            fl.addEventListener( 'change', _chng );
        });
    });
}));
