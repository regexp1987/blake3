--TEST--
blake3() keyed mode (MAC) — strict vector verification
--SKIPIF--
<?php if ( !extension_loaded('blake3') ) die( 'skip blake3 extension not loaded' ); ?>
--FILE--
<?php
  $sKey = implode('', array_map('chr', array_map('hexdec',
    str_split('3031323334353637383961626364656630313233343536373839616263646566', 2))));

  $uPass = 0;
  $uFail = 0;

  function fnVerify( string $sLabel, mixed $mActual, mixed $mExpected ) : void
  {
    global $uPass, $uFail;

    if ( $mActual === $mExpected )
    {
      $uPass++;
      echo "OK  $sLabel\n";
    }
    else
    {
      $uFail++;
      echo "FAIL $sLabel\n  got:    $mActual\n  expect: $mExpected\n";
    }
  }

  fnVerify( 'keyed_empty',   blake3('', 32, $sKey),      '81591338b3d8b9dc4ff3b228cdd28b23df07fcecb1e2e77c4725beeccd77e916' );
  fnVerify( 'keyed_hello',   blake3('hello', 32, $sKey),  '14a41e9be55a5ced1b264d9f82dc0dcead598a4279710e28dadd0b0f5f4fcbdb' );
  fnVerify( 'keyed_message', blake3('message', 32, $sKey), '0375fb06e058b29b01dda52184b59c3fb1cbf0230e4d45168c6c28928f6b8577' );

  $sMac = blake3( 'test', 32, $sKey );
  fnVerify( 'keyed_hex_len', strlen($sMac), 64 );
  fnVerify( 'keyed_hex_fmt', preg_match('/^[0-9a-f]{64}$/', $sMac), 1 );

  fnVerify( 'keyed_deterministic', blake3('test', 32, $sKey) === $sMac, TRUE );

  $sKey2 = str_repeat("\xff", 32);
  fnVerify( 'keyed_diff_key', blake3('test', 32, $sKey2) !== $sMac, TRUE );

  $sRaw = blake3( 'test', 32, $sKey, TRUE );
  fnVerify( 'keyed_raw_len', strlen($sRaw), 32 );
  fnVerify( 'keyed_raw_hex', bin2hex($sRaw), $sMac );

  fnVerify( 'keyed_compat', blake3_keyed_hash('test', $sKey), $sMac );

  $sErr = '';
  try { blake3( 'x', 32, 'short' ); } catch ( ValueError $oEx ) { $sErr = $oEx->getMessage(); }
  fnVerify( 'keyed_short_key', strpos($sErr, '32') !== FALSE, TRUE );

  try { blake3( 'x', 32, str_repeat('a', 31) ); } catch ( ValueError $oEx ) { $sErr = $oEx->getMessage(); }
  fnVerify( 'keyed_31_bytes', strpos($sErr, '32') !== FALSE, TRUE );

  try { blake3( 'x', 32, str_repeat('a', 33) ); } catch ( ValueError $oEx ) { $sErr = $oEx->getMessage(); }
  fnVerify( 'keyed_33_bytes', strpos($sErr, '32') !== FALSE, TRUE );

  echo "\n$uPass passed, $uFail failed\n";
?>
--EXPECT--
OK  keyed_empty
OK  keyed_hello
OK  keyed_message
OK  keyed_hex_len
OK  keyed_hex_fmt
OK  keyed_deterministic
OK  keyed_diff_key
OK  keyed_raw_len
OK  keyed_raw_hex
OK  keyed_compat
OK  keyed_short_key
OK  keyed_31_bytes
OK  keyed_33_bytes

13 passed, 0 failed
