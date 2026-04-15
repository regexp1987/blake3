--TEST--
blake3() one-shot hash — strict upstream-verified vectors
--SKIPIF--
<?php if ( !extension_loaded('blake3') ) die( 'skip blake3 extension not loaded' ); ?>
--FILE--
<?php
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

  fnVerify( 'empty',    blake3(''),           'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262' );
  fnVerify( 'hello',    blake3('hello'),       'ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f' );
  fnVerify( 'hw',       blake3('hello world'), 'd74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24' );
  fnVerify( 'space',    blake3(' '),           '00263ca9f57f7177f495e3711f8cdd59967a0a1a4de895b1ebee566cd1883ed4' );
  fnVerify( 'newline',  blake3("\n"),          '295192ea1ec8566d563b1a7587e5f0198580cdbd043842f5090a4c197c20c67a' );
  fnVerify( 'tab',      blake3("\t"),          '7219aa1099ced7445c5bf949990ff7d9f6b71a94b8ec02b3eb61fb175a66ba25' );
  fnVerify( 'crlf',     blake3("\r\n"),        '3de3577a7c26681bdae91dbd9b8dcfebaef16fd2b3b82d3369b230feadf51961' );
  fnVerify( 'digits',   blake3('0123456789'), '53b63a6fc8605d0c0ce559317a00177d72adb24d669235e4c914f443a8831ca1' );
  fnVerify( 'octal',    blake3('01234567'),   '47d79120c9171189a6607ad9c56019ca79a158d242c40e443b02e1004b1cc3d3' );

  fnVerify( 'byte_0x00',  blake3("\x00"),                              '2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213' );
  fnVerify( 'byte_0xff',  blake3("\xff"),                              '99d44d377bc5936d8cb7f5df90713d84c7587739b4724d3d2f9af1ee0e4c8efd' );
  fnVerify( 'byte_0x7f',  blake3("\x7f"),                              'c66834cb4da1d8da1f6d7fc0cdb7f8643b1daf099801c3acbc198260c88a371a' );
  fnVerify( 'byte_0x80',  blake3("\x80"),                              'bbe6a9f5a0146a1f4d0381e9b0ed1ac2f1a979ce9d5ad84e46ff0b58f36b5f46' );
  fnVerify( 'high_bytes', blake3("\x80\x81\xfe\xff"),                  '052a86c63a5b50ab10a19a0cda0a4c8fc5a9d788c4e7f0d5821a6cf82b5eb96f' );
  fnVerify( 'binary_16',  blake3(implode('', array_map('chr', range(0, 15)))), 'a6a492965517a830cb75fdb713465aa465f2f098233896fea44c1d98268bf9e3' );
  fnVerify( 'null_8',     blake3("\x00\x00\x00\x00\x00\x00\x00\x00"), '71e0a99173564931c0b8acc52d2685a8e39c64dc52e3d02390fdac2a12b155cb' );

  fnVerify( 'emoji', blake3("\xF0\x9F\x94\x90\xF0\x9F\x9A\x80\xF0\x9F\xA7\xA0"), 'a659fc0d659c919fbd1a82b1c0a73ab7a9e590eb337f57ef17ebdf3776a8e01b' );
  fnVerify( 'cjk',   blake3("\xE4\xBD\xA0\xE5\xA5\xBD\xE4\xB8\x96\xE7\x95\x8C"), '43198a190cbfb992c88864ef5185451d88843819089a3a1d461ea22f18fba4dc' );

  fnVerify( 'json', blake3('{}'), '6e46dd10defc9b56c29a6ec56b508c21f54c08192194e4df25bf36f0c9c3c279' );

  fnVerify( 'chunk_64',   blake3(str_repeat('X', 64)),   'fed747ac1c4bed0deedf71d7e74b0d0f9c6c3338dcf2636cb09712b263eade57' );
  fnVerify( 'chunk_65',   blake3(str_repeat('X', 65)),   '32b1b5b5cf0130f394b5c5edd4dd2776c9f4abafa0c6b2924a4e4b959d3e5343' );
  fnVerify( 'chunk_1023', blake3(str_repeat('X', 1023)), 'dae45eb90b189b177c45f67147dcc2693ffa2ecca5999b83194ab20c4405b2a5' );
  fnVerify( 'chunk_1024', blake3(str_repeat('X', 1024)), 'ce7abb2491c2e7e30ce379886d7fada219eb45ab76051a88fe3df6f27fc0ac28' );
  fnVerify( 'chunk_1025', blake3(str_repeat('X', 1025)), 'c415391387792ae873b9211b6a85da890710f26d1911e6ee892936861a67d12a' );

  fnVerify( 'hello_1',   blake3('hello', 1),   'ea' );
  fnVerify( 'hello_2',   blake3('hello', 2),   'ea8f' );
  fnVerify( 'hello_4',   blake3('hello', 4),   'ea8f163d' );
  fnVerify( 'hello_8',   blake3('hello', 8),   'ea8f163db3868292' );
  fnVerify( 'hello_16',  blake3('hello', 16),  'ea8f163db38682925e4491c5e58d4bb3' );
  fnVerify( 'hello_64',  blake3('hello', 64),  'ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200fe992405f0d785b599a2e3387f6d34d01faccfeb22fb697ef3fd53541241a338c' );
  fnVerify( 'hello_128', blake3('hello', 128), 'ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200fe992405f0d785b599a2e3387f6d34d01faccfeb22fb697ef3fd53541241a338cc68876568ab5c6e524abbcfe881e5b4e1ac9336f3f932d412248c9829536699f07a1b1ce35ffdfe0be5d00c083a8dfd29c9a4303d1374cd70e6abcec6e6b796c' );
  fnVerify( 'hello_256', blake3('hello', 256), 'ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200fe992405f0d785b599a2e3387f6d34d01faccfeb22fb697ef3fd53541241a338cc68876568ab5c6e524abbcfe881e5b4e1ac9336f3f932d412248c9829536699f07a1b1ce35ffdfe0be5d00c083a8dfd29c9a4303d1374cd70e6abcec6e6b796c92ac0509cfc19daa69696e734ccf290070cf058f0fdec93fb61d096d082eaaf40872c12cfb8c6e272ed6112254f21885074d94153ff112ab65cc4a4dbace93fe9f584e9feae7a86312e6ed4ca558b343f6397c454f47ff9a2451f6630d45c23fcf9cc6f09fc6d32b5d7a74952c2f34f903cc42939899a90dd16d0d46003edecd' );

  $sMb = blake3( str_repeat('C', 1048576) );
  fnVerify( '1mb_len', strlen($sMb), 64 );
  fnVerify( '1mb_fmt', preg_match('/^[0-9a-f]{64}$/', $sMb), 1 );

  $sRaw = blake3( 'hello', 32, NULL, TRUE );
  fnVerify( 'raw_len', strlen($sRaw), 32 );
  fnVerify( 'raw_hex', bin2hex($sRaw), 'ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f' );

  fnVerify( 'null_key', blake3('data', 32, NULL), blake3('data') );

  echo "\n$uPass passed, $uFail failed\n";
?>
--EXPECT--
OK  empty
OK  hello
OK  hw
OK  space
OK  newline
OK  tab
OK  crlf
OK  digits
OK  octal
OK  byte_0x00
OK  byte_0xff
OK  byte_0x7f
OK  byte_0x80
OK  high_bytes
OK  binary_16
OK  null_8
OK  emoji
OK  cjk
OK  json
OK  chunk_64
OK  chunk_65
OK  chunk_1023
OK  chunk_1024
OK  chunk_1025
OK  hello_1
OK  hello_2
OK  hello_4
OK  hello_8
OK  hello_16
OK  hello_64
OK  hello_128
OK  hello_256
OK  1mb_len
OK  1mb_fmt
OK  raw_len
OK  raw_hex
OK  null_key

37 passed, 0 failed
