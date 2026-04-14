--TEST--
blake3_reset() — reinitialise context
--SKIPIF--
<?php if ( !extension_loaded('blake3') ) die( 'skip blake3 extension not loaded' ); ?>
--FILE--
<?php
  $oCtx = blake3_init();
  blake3_update( $oCtx, 'hello' );
  $sHash1 = blake3_final( $oCtx );

  blake3_reset( $oCtx );
  blake3_update( $oCtx, 'hello' );
  $sHash2 = blake3_final( $oCtx );
  echo 'Reset after final: ' . ( $sHash1 === $sHash2 ? 'yes' : 'no' ) . "\n";

  $sKey = str_repeat( 'k', 32 );
  blake3_reset( $oCtx, $sKey );
  blake3_update( $oCtx, 'message' );
  $sMac = blake3_final( $oCtx );
  echo 'Reset with key: ' . ( $sMac === blake3('message', 32, $sKey) ? 'yes' : 'no' ) . "\n";

  try { blake3_reset( $oCtx, 'short' ); } catch ( ValueError $oE ) { echo "Reset key error: yes\n"; }
  try { blake3_reset( 'not a context' ); } catch ( TypeError $oE ) { echo "Reset type error: yes\n"; }
?>
--EXPECT--
Reset after final: yes
Reset with key: yes
Reset key error: yes
Reset type error: yes
