--TEST--
Error handling — invalid arguments
--SKIPIF--
<?php if ( !extension_loaded('blake3') ) die( 'skip blake3 extension not loaded' ); ?>
--FILE--
<?php
  try { blake3( 'data', 0 ); }  catch ( ValueError $oE ) { echo "blake3 zero: yes\n"; }
  try { blake3( 'data', -1 ); } catch ( ValueError $oE ) { echo "blake3 negative: yes\n"; }
  try { blake3( 'data', 32, 'short' ); } catch ( ValueError $oE ) { echo "blake3 key: yes\n"; }

  try { blake3_update( 'not a context', 'data' ); } catch ( TypeError $oE ) { echo "update type: yes\n"; }
  try { blake3_final( 'not a context' ); }          catch ( TypeError $oE ) { echo "final type: yes\n"; }

  try { blake3_hash( 'data', 0 ); }          catch ( ValueError $oE ) { echo "hash zero: yes\n"; }
  try { blake3_keyed_hash( 'data', 'short' ); } catch ( ValueError $oE ) { echo "keyed key: yes\n"; }
  try { blake3_xof( 'data', 0 ); }           catch ( ValueError $oE ) { echo "xof zero: yes\n"; }
  try { blake3_file( __FILE__, 0 ); }        catch ( ValueError $oE ) { echo "file zero: yes\n"; }

  $oCtx = blake3_init();
  try { blake3_reset( $oCtx, 'short' ); } catch ( ValueError $oE ) { echo "reset key: yes\n"; }
  try { blake3_reset( 'nope' ); }          catch ( TypeError $oE )  { echo "reset type: yes\n"; }

  echo 'BLAKE3_OUT_LEN: '   . BLAKE3_OUT_LEN   . "\n";
  echo 'BLAKE3_KEY_LEN: '   . BLAKE3_KEY_LEN   . "\n";
  echo 'BLAKE3_BLOCK_LEN: ' . BLAKE3_BLOCK_LEN . "\n";
  echo 'BLAKE3_MAX_DEPTH: ' . BLAKE3_MAX_DEPTH . "\n";
  echo 'BLAKE3_MAX_OUTPUT: ' . BLAKE3_MAX_OUTPUT . "\n";
?>
--EXPECT--
blake3 zero: yes
blake3 negative: yes
blake3 key: yes
update type: yes
final type: yes
hash zero: yes
keyed key: yes
xof zero: yes
file zero: yes
reset key: yes
reset type: yes
BLAKE3_OUT_LEN: 32
BLAKE3_KEY_LEN: 32
BLAKE3_BLOCK_LEN: 64
BLAKE3_MAX_DEPTH: 54
BLAKE3_MAX_OUTPUT: 67108864
