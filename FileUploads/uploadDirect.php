<?php

/**
 *
 * Upload File Directly (Handler)
 *
 * Use:
 *        $uploader = new UploadFilesDirectly()
 *
 *        $_FILES[ varname ]...
 *
 *        $uploader->response ( [optional error message] )
 *
 * @author istem
 */

class UploadFilesDirectly
{
    public $EXISTS = false;

    public $VARNAME = '';
   
    public $FILE = array
    (
        'name'     => '',
        'tmp_name' => '',
        'error'    => -1,
        'size'     => 0,
    );

    public function __construct()
    {
        if (
            isset ( $_SERVER['HTTP_X_FILE_UPLOAD'] )
            &&
            $_SERVER['REQUEST_METHOD'] == 'POST'
        ) {
            $this->EXISTS = true;

            $this->_process ();
           
            $_FILES [ $this->VARNAME ] = $this->FILE;
        }
    }
   
    public function response ( $success=null, $error='' )
    {
        if ( ! $this->EXISTS )
        {
            return;
        }
       
        $errors = array
        (
            -1                    => 'Unknown error',
            UPLOAD_ERR_OK         => '',
            UPLOAD_ERR_FORM_SIZE  => 'Max files upload esceed',
            UPLOAD_ERR_NO_TMP_DIR => 'Error create tmp file',
            UPLOAD_ERR_EXTENSION  => 'Error open tmp file',
            UPLOAD_ERR_CANT_WRITE => 'Failed writing file',
            UPLOAD_ERR_NO_FILE    => 'File is empty',
            UPLOAD_ERR_INI_SIZE   => 'File size exceed',
        );

        $out = array
        (
            'success' => ($success === null) ? ( $this->FILE['error'] == UPLOAD_ERR_OK ) : $success,
            'error'   => $error ? $error : $errors [ $this->FILE['error'] ],
        );

        header('Content-Type: application/json');
        echo json_encode ( $out, JSON_UNESCAPED_UNICODE );
        exit();
    }

    private function _process ()
    {
        // get variables
        $this->VARNAME = trim( urldecode ( $_SERVER['HTTP_X_FILE_UPLOAD'] ), "[] \s\t\n\r\v\0" );
        if ( empty ( $this->VARNAME ) )
        {
            $this->VARNAME = uniqid();
        }

        // check max files upload
        if ( ! $this->_count() )
        {
            $this->FILE['error'] = UPLOAD_ERR_FORM_SIZE;
            return;
        }

        $file_name = urldecode ( isset ( $_SERVER['HTTP_X_FILE_NAME'] ) ? $_SERVER['HTTP_X_FILE_NAME'] : uniqid() );

        // check filename length
        $partsd = explode ( '/', $file_name );
        $file_name = array_pop ( $partsd );

        $partse = explode ( '.', $file_name );
        $ext    = array_pop ( $partse );
        $name   = implode ( '.', $partse );

        if ( mb_strlen ( $name, 'UTF-8' ) > 128 )
        {
            $name = mb_substr ( $name, 0, 128, 'UTF-8');
            $file_name = $name . '.' . $ext;
        }

        $this->FILE['name'] = $file_name;

        // prepare check size
        $max_size = $this->_parse_ini_var ( 'upload_max_filesize' );

        $content_length = isset ( $_SERVER['CONTENT_LENGTH'] )
                ? (int)$_SERVER['CONTENT_LENGTH']
                : (
                    isset ( $_SERVER['HTTP_CONTENT_LENGTH'] )
                    ? (int)$_SERVER['HTTP_CONTENT_LENGTH']
                    : 0
                );
        if ( $content_length > $max_size )
        {
            $this->FILE['error'] = UPLOAD_ERR_INI_SIZE;
            return;
        }

        // upload...

        $temp_name = tempnam ( sys_get_temp_dir(), 'uf-' );
        if ( $temp_name === false )
        {
            $this->FILE['error'] = UPLOAD_ERR_NO_TMP_DIR;
            return;
        }

        $buffer = fopen ( 'php://input', 'r' );

        if ( $buffer === false )
        {
            $this->FILE['error'] = UPLOAD_ERR_EXTENSION;
            unlink ( $temp_name );
            return;
        }

        $bytes = file_put_contents ( $temp_name, $buffer );
        fclose ( $buffer );

        if ( $bytes === false )
        {
            $this->FILE['error'] = UPLOAD_ERR_CANT_WRITE;
            unlink ( $temp_name );
            return;
        }

        $this->FILE['size'] = $bytes;

        if ( $bytes === 0 )
        {
            $this->FILE['error'] = UPLOAD_ERR_NO_FILE;
            unlink ( $temp_name );
            return;
        }

        // check file size
        if ( $bytes > $max_size )
        {
            $this->FILE['error'] = UPLOAD_ERR_INI_SIZE;
            unlink ( $temp_name );
            return;
        }

        $this->FILE['error'] = UPLOAD_ERR_OK;
        $this->FILE['tmp_name'] = $temp_name;

        register_shutdown_function ( 'unlink', $temp_name );
    }

    private function _count ( )
    {
        $out = false;

        $allow = array
        (
            'wait_lock'         => 20,
            'upload_time'       => 3600,
            'max_files_per_ip'  => $this->_parse_ini_var ( 'max_file_uploads' ),
            'max_connections'   => 20,
        );
        $now = time();

        $counter_name = dirname ( __FILE__ ) . '/counter.json';

        if ( ! file_exists ( $counter_name ) )
        {
            touch ( $counter_name );
        }

        $wait = $now + $allow['wait_lock'];

        $handler = fopen ( $counter_name, 'c+' );
        while ( ! flock ( $handler, LOCK_EX | LOCK_NB ) )
        {
            if ( time() > $wait )
            {
                fclose ( $handler );
                return $out;
            }

            usleep ( round( mt_rand (1, 100) * 1000 ) );
        }

        $json = fread ( $handler, filesize ( $counter_name ) );
        if ( empty ( $json ) )
        {
            $json = '{}';
        }
        $data = json_decode ( $json, 1 );

        $end = $now - $allow['upload_time'];

        foreach ( $data as $ip => $times )
        {
            $clear = array_filter (
                $times,
                function ( $time ) use ( $end )
                {
                    return $time > $end;
                }
            );
            if ( ! sizeof ( $clear ) )
            {
                unset ( $data[ $ip ] );
            }
            else
            {
                $data[ $ip ] = array_values ( $clear );
            }
        }

        if ( sizeof ( $data ) > $allow['max_connections'] )
        {
            // return false
        }
        elseif (
            ! empty ( $data[ $_SERVER['REMOTE_ADDR'] ] )
            &&
            sizeof ( $data[ $_SERVER['REMOTE_ADDR'] ] ) >= $allow['max_files_per_ip']
        ) {
            // return false
        }
        else
        {
            if ( ! isset($data[ $_SERVER['REMOTE_ADDR'] ]) )
            {
                $data[ $_SERVER['REMOTE_ADDR'] ] = array();
            }
            $data[ $_SERVER['REMOTE_ADDR'] ][] = $now;

            $out = true;
        }

        $json = json_encode ( $data );

        rewind ( $handler );
        fwrite ( $handler, $json );

        fflush ( $handler );
        ftruncate ( $handler, ftell ( $handler ) );

        flock ( $handler, LOCK_UN );
        fclose ( $handler );

        return $out;
    }

    private function _parse_ini_var ( $inivar )
    {
        $var = ini_get ( $inivar );
        $out = 0;

        if ( preg_match('/^(\d+)(\D+)$/', $var, $matches) )
        {
            $quant = array(
                    'TI' => 1024*1024*1024*1024,
                    'TB' => 1000*1000*1000*1000,
                    'T'  => 1000*1000*1000*1000,
                    'GI' => 1024*1024*1024,
                    'GB' => 1000*1000*1000,
                    'G'  => 1000*1000*1000,
                    'MI' => 1024*1024,
                    'MB' => 1000*1000,
                    'M'  => 1000*1000,
                    'KI' => 1024,
                    'KB' => 1000,
                    'K'  => 1000,
                );

            $mul = isset( $quant[ strtoupper(trim($matches[2])) ] )
                    ? $quant[ strtoupper(trim($matches[2])) ]
                    : 1
                ;
            $out = $matches[1] * $mul;
        }
        else if (
            is_numeric($var)
            && (int)$var > 0
        ) {
            $out = (int)$var;
        }
        else if ( $var === '-1' )
        {
             $out = 268435456; // 256Mi
        }

        return $out;
    }
}
