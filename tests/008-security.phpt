--TEST--

Security — DoS prevention, edge cases, constants
--SKIPIF--
<?php if ( !extension_loaded('blake3') )
    die( 'skip blake3 extension not loaded' );
?>
--FILE--
<?php
  echo 'BLAKE3_MAX_OUTPUT defined: ' . ( defined('BLAKE3_MAX_OUTPUT') ? 'yes' : 'no' ) . "\n";
  echo 'BLAKE3_MAX_OUTPUT value: '   . ( BLAKE3_MAX_OUTPUT === 64 * 1024 * 1024 ? '67108864' : 'unexpected' ) . "\n";

  try { blake3( 'data', 100000000 ); }     catch ( ValueError $oE ) { echo "Too big rejected: yes\n"; }
  try { blake3_xof( 'data', 100000000 ); } catch ( ValueError $oE ) { echo "XOF too big: yes\n"; }

  try { new Blake3Context(); }
  catch ( Throwable $oE ) { echo 'New blocked: ' . ( strpos($oE->getMessage(), 'blake3_init') !== FALSE ? 'yes' : 'no' ) . "\n"; }

  $rClass = new ReflectionClass( 'Blake3Context' );
  echo 'Extend blocked: ' . ( $rClass->isFinal() ? 'yes' : 'no' ) . "\n";

  try { blake3_file( '' ); } catch ( ValueError $oE ) { echo "Empty filename: yes\n"; }

  $uI = 0;
  while ( $uI < 10 )
  {
    try { new Blake3Context(); } catch ( Throwable $_ ) { }
    ++$uI;
  }
  echo "New loop 10x: no crash\n";

  $oCtx = blake3_init();
  $oClone = clone $oCtx;
  blake3_update( $oClone, 'test' );
  echo 'Clone works: ' . ( blake3_final($oClone) === blake3('test') ? 'yes' : 'no' ) . "\n";

  try { serialize( blake3_init() ); } catch ( Throwable $oE ) { echo "Serialise blocked: yes\n"; }

  set_error_handler( function( $iErr, $sMsg ) { throw new Error($sMsg); } );
  try { unserialize( 'O:15:"Blake3Context":0:{}' ); } catch ( Throwable $oE ) { echo "Unserialise blocked: yes\n"; }
  restore_error_handler();

  $sEmpty = blake3( '' );
  echo 'Empty valid: ' . ( strlen($sEmpty) === 64 ? 'yes' : 'no' ) . "\n";

  $sLarge = str_repeat( 'x', 1024 * 1024 );
  $sHash  = blake3( $sLarge );
  echo 'Large input: ' . ( strlen($sHash) === 64 ? 'yes' : 'no' ) . "\n";

  $sWithNull    = blake3( 'data', 32, NULL );
  $sWithoutKey  = blake3( 'data' );
  echo 'Null key == no key: ' . ( $sWithNull === $sWithoutKey ? 'yes' : 'no' ) . "\n";
?>
--EXPECT--
BLAKE3_MAX_OUTPUT defined: yes
BLAKE3_MAX_OUTPUT value: 67108864
Too big rejected: yes
XOF too big: yes
New blocked: yes
Extend blocked: yes
Empty filename: yes
New loop 10x: no crash
Clone works: yes
Serialise blocked: yes
Unserialise blocked: yes
Empty valid: yes
Large input: yes
Null key == no key: yes
