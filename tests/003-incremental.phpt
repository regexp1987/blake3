--TEST--
blake3_init / blake3_update / blake3_final — incremental hashing
--SKIPIF--
<?php if ( !extension_loaded('blake3') ) die( 'skip blake3 extension not loaded' ); ?>
--FILE--
<?php
  $oCtx = blake3_init();
  blake3_update( $oCtx, 'hel' );
  blake3_update( $oCtx, 'lo' );
  $sHash = blake3_final( $oCtx );
  echo 'Incremental matches one-shot: ' . ( $sHash === blake3('hello') ? 'yes' : 'no' ) . "\n";

  $oCtx2 = blake3_init();
  blake3_update( $oCtx2, 'hello' );
  $sRaw = blake3_final( $oCtx2, TRUE );
  echo 'Raw length: ' . strlen( $sRaw ) . "\n";
  echo 'Raw matches hex: ' . ( bin2hex($sRaw) === $sHash ? 'yes' : 'no' ) . "\n";

  $sKey = str_repeat( 'k', 32 );
  $oCtx3 = blake3_init( $sKey );
  blake3_update( $oCtx3, 'message' );
  $sMac = blake3_final( $oCtx3 );
  echo 'Keyed matches: ' . ( $sMac === blake3('message', 32, $sKey) ? 'yes' : 'no' ) . "\n";

  try { blake3_update( $oCtx, 'more data' ); } catch ( Error $oE ) { echo "Consumed error: yes\n"; }

  try { blake3_init( 'short' ); } catch ( ValueError $oE ) { echo "Init key error: yes\n"; }

  $oOop = blake3_init();
  $oOop->update( 'hel' );
  $oOop->update( 'lo' );
  $sOopHash = $oOop->final();
  echo 'OOP matches: ' . ( $sOopHash === blake3('hello') ? 'yes' : 'no' ) . "\n";

  try { $oOop->final(); } catch ( Error $oE ) { echo "OOP double final: yes\n"; }

  try { $oOop->update( 'more' ); } catch ( Error $oE ) { echo "OOP update after final: yes\n"; }
?>
--EXPECT--
Incremental matches one-shot: yes
Raw length: 32
Raw matches hex: yes
Keyed matches: yes
Consumed error: yes
Init key error: yes
OOP matches: yes
OOP double final: yes
OOP update after final: yes
