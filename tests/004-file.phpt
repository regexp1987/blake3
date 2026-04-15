--TEST--
blake3_file() — streaming file hash
--SKIPIF--
<?php if ( !extension_loaded('blake3') ) die( 'skip blake3 extension not loaded' ); ?>
--FILE--
<?php
  $sTmp = sys_get_temp_dir() . '/blake3_test_' . uniqid() . '.tmp';
  file_put_contents( $sTmp, 'hello' );

  $sHash = blake3_file( $sTmp );
  echo 'Type: ' . gettype( $sHash ) . "\n";
  echo 'Length: ' . strlen( $sHash ) . "\n";
  echo 'Matches one-shot: ' . ( $sHash === blake3('hello') ? 'yes' : 'no' ) . "\n";

  $sRaw = blake3_file( $sTmp, 32, NULL, TRUE );
  echo 'Raw matches: ' . ( bin2hex($sRaw) === $sHash ? 'yes' : 'no' ) . "\n";

  $sShort = blake3_file( $sTmp, 16 );
  echo 'Short length: ' . strlen( $sShort ) . "\n";

  $bMissing = @blake3_file( '/nonexistent/file/path' );
  echo 'Missing file returns FALSE: ' . ( $bMissing === FALSE ? 'yes' : 'no' ) . "\n";

  $sKey = str_repeat( 'k', 32 );
  $sMac = blake3_file( $sTmp, 32, $sKey );
  echo 'File keyed len: ' . strlen( $sMac ) . "\n";
  echo 'File keyed match: ' . ( $sMac === blake3('hello', 32, $sKey) ? 'yes' : 'no' ) . "\n";

  $sRawKeyed = blake3_file( $sTmp, 32, $sKey, TRUE );
  echo 'File keyed raw: ' . ( bin2hex($sRawKeyed) === $sMac ? 'yes' : 'no' ) . "\n";

  unlink( $sTmp );
?>
--EXPECT--
Type: string
Length: 64
Matches one-shot: yes
Raw matches: yes
Short length: 32
Missing file returns FALSE: yes
File keyed len: 64
File keyed match: yes
File keyed raw: yes
