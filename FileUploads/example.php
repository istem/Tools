<?php
/**
 * Example to use directly Uploader File
 * 
 *
 * Worked for:
 *    <form class="direct-upload"> <input type="file">
 *
 * [Optional]
 *    <input type="file" data-callback="callbackFunc">
 *
 *    window.callbackFunc ( array messages : statuses uploaded file[s] )
 *
 * @author istem
 */

require __DIR__ . '/uploadDirect.php';

$uploader = new UploadDirect();

// only one file by one time
if ( isset ( $_FILES['my-pretty-input-name'] ) )
{
  if ( $_FILES['my-pretty-input-name']['error'] === UPLOAD_ERR_OK )
  {
    // ordinary file operations...
    $sanitizedName = str_replace ( ['\\', '/'], '', $_FILES['my-pretty-input-name']['name'] );
    $newFilename   = './dir_uploads/' . $sanitizedName;
    
    $success = rename ( $_FILES['my-pretty-input-name']['tmp_name'], $newFilename );
    //$success = copy ( $_FILES['my-pretty-input-name']['tmp_name'], $newFilename ); // for diff filesystems
  }
  
  $uploader->response ( $success );
  exit();
}

?>
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>My Super Puper Site</title>
    <script src="./uploadDirect.js"></script>
    <script>
      function callbackUpload ( messages )
      {
        alert ( messages.join(',') );
      }
    </script>
  </head>
  <body>
    <form action="" class="direct-upload" method="">
      <input type="file" name="my-pretty-input-name" data-callback="callbackUpload" multiple />
    </form>
  </body>
</html>
