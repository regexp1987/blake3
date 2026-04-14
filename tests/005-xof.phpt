--TEST--
blake3_xof() — extendable output function
--SKIPIF--
<?php if ( !extension_loaded('blake3') ) die( 'skip blake3 extension not loaded' ); ?>
--FILE--
<?php
  $sHash64 = blake3_xof( 'data', 64 );
  echo '64 bytes to 128 hex: ' . ( strlen($sHash64) === 128 ? 'yes' : 'no' ) . "\n";

  $sHash4 = blake3_xof( 'data', 4 );
  echo '4 bytes to 8 hex: ' . ( strlen($sHash4) === 8 ? 'yes' : 'no' ) . "\n";

  $sBlake3_4 = blake3( 'data', 4 );
  echo 'XOF matches blake3: ' . ( $sHash4 === $sBlake3_4 ? 'yes' : 'no' ) . "\n";

  $sKey = str_repeat( 'k', 32 );
  $sMac = blake3_xof( 'data', 32, $sKey );
  echo 'Keyed xof: ' . ( strlen($sMac) === 64 ? 'yes' : 'no' ) . "\n";
  echo 'Keyed matches: ' . ( $sMac === blake3('data', 32, $sKey) ? 'yes' : 'no' ) . "\n";

  $sRaw = blake3_xof( 'data', 4, NULL, TRUE );
  echo 'Raw output len: ' . ( strlen($sRaw) === 4 ? 'yes' : 'no' ) . "\n";
  echo 'Raw matches hex: ' . ( bin2hex($sRaw) === $sHash4 ? 'yes' : 'no' ) . "\n";

  try { blake3_xof( 'data', 0 ); } catch ( ValueError $oE ) { echo "Zero error: yes\n"; }
?>
--EXPECT--
64 bytes to 128 hex: yes
4 bytes to 8 hex: yes
XOF matches blake3: yes
Keyed xof: yes
Keyed matches: yes
Raw output len: yes
Raw matches hex: yes
Zero error: yes
