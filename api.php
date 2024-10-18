<?php
    require __DIR__ . '/vendor/autoload.php';
    use Elliptic\EC;
    // Utils helper class
    class Utils {
        
        public static function hex2bin($str) {
            return hex2bin(strlen($str) % 2 == 1 ? "0" . $str : $str);
        }
        
        public static function substring($str, $start, $end) {
            return substr($str, $start, $end - $start);
        }
        
        public static function arrayValue($array, $key, $default = false) {
            return array_key_exists($key, $array) ? $array[$key] : $default;
        }
    }
    // Crypto helper class
    class Crypto {
        
        public static function hmacSha256($key, $data) {
            return hash_hmac("sha256", $data, $key, true);
        }
        
        public static function aes256GcmPkcs7Encrypt($data, $key, $iv) {
            $encrypted = openssl_encrypt($data, 'AES-256-GCM', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
            return $encrypted.$tag;
        }
        
        public static function aes256GcmPkcs7Decrypt($data, $key, $iv) {
            $tag = substr($data, strlen($data) - 16);
            $data = substr($data, 0, strlen($data) - 16);
            return openssl_decrypt($data, 'AES-256-GCM', $key, OPENSSL_RAW_DATA, $iv, $tag);
        }
    }
    // ECIES helper class
    class ECIES {
        
        private $privateKey;
        private $publicKey;
        private $rBuf;
        private $kEkM;
        private $kE;
        private $kM;
        private $opts;
        
        public function __construct($privateKey, $publicKey, $opts = array("noKey" => true, "shortTag" => true)) {
            $this->privateKey = $privateKey;
            $this->publicKey = $publicKey;
            $this->opts = $opts;
        }

        public function getRbuf() {
            if (is_null($this->rBuf)) {
                $this->rBuf = Utils::hex2bin($this->privateKey->getPublic(true, "hex"));
            }
            return $this->rBuf;
        }

        private function getSharedKey()
        {
            $shared = $this->privateKey->derive($this->publicKey->getPublic());
            $bin = Utils::hex2bin( $shared->toString("hex") );
            return hash("sha512", $bin, true);
        }
        
        public function getkEkM() {
            if (is_null($this->kEkM)) {
                $this->kEkM = $this->getSharedKey();
            }
            return $this->kEkM;
        }
        
        public function getkE() {
            if (is_null($this->kE)) {
                $this->kE = Utils::substring($this->getkEkM(), 0, 32);
            }
            return $this->kE;
        }
        
        public function getkM() {
            if (is_null($this->kM)) {
                $this->kM = Utils::substring($this->getkEkM(), 32, 64);
            }
            return $this->kM;
        }

        private function getPrivateEncKey()
        {
            $hex = $this->privateKey->getPrivate("hex");
            return Utils::hex2bin( $hex );
        }
        
        public function encrypt($message, $ivbuf = null) {
            if (is_null($ivbuf)) {
                $ivbuf = Utils::substring(Crypto::hmacSha256($this->getPrivateEncKey(), $message), 0, 16);
            }
            $c = $ivbuf . Crypto::aes256GcmPkcs7Encrypt($message, $this->getkE(), $ivbuf);
            $d = Crypto::hmacSha256($this->getkM(), $c);
            if (Utils::arrayValue($this->opts, "shortTag")) {
                $d = Utils::substring($d, 0, 4);
            }
            if (Utils::arrayValue($this->opts, "noKey")) {
                $encbuf = $c . $d;
            }
            else {
                $encbuf = $this->getRbuf() . $c . $d;
            }
            return $encbuf;
        }
        
        public function decrypt($encbuf) {
            $offset = 0;
            $tagLength = 32;
            if (Utils::arrayValue($this->opts, "shortTag")) {
                $tagLength = 4;
            }
            if (!Utils::arrayValue($this->opts, "noKey")) {
                $offset = 33;
                $this->publicKey = Utils::substring($encbuf, 0, 33);
            }
            
            $c = Utils::substring($encbuf, $offset, strlen($encbuf) - $tagLength);
            $d = Utils::substring($encbuf, strlen($encbuf) - $tagLength, strlen($encbuf));
            
            $d2 = Crypto::hmacSha256($this->getkM(), $c);
            if (Utils::arrayValue($this->opts, "shortTag")) {
                $d2 = Utils::substring($d2, 0, 4);
            }
            
            $equal = true;
            for ($i = 0; $i < strlen($d); $i++) {
                $equal &= ($d[$i] === $d2[$i]);
            }
            if (!$equal) {
                throw new \Exception("Invalid checksum");
            }
            
            return Crypto::aes256GcmPkcs7Decrypt(Utils::substring($c, 16, strlen($c)), $this->getkE(), Utils::substring($c, 0, 16));
        }
    }
    // Generate PHP keys
    function generateKeysPHP() {
        $ec = new EC('secp256k1');
        // Generate keys
        // $private_key = $ec->genKeyPair();
        // $public_key = $ec->keyFromPublic($private_key->getPublic());
        $key = $ec->genKeyPair();
        $private_key = $key->getPrivate("hex");
        $public_key = $key->getPublic("hex");
        return [
            'privateKey' => $private_key,
            'publicKey' => $public_key,

        ];
    }
    // Encrypt with PHP
    function encrypt($message, $privateKey, $publicKey) {
        $ec = new EC('secp256k1');
        $private_key = $ec->keyFromPrivate($privateKey, 'hex');
        $public_key = $ec->keyFromPublic($publicKey, 'hex');

        $ecies = new ECIES($private_key, $public_key);
        $cipher = $ecies->encrypt($message);
        
        return bin2hex($cipher);
    }

    // Decrypt with PHP
    function decrypt($cipher, $privateKey, $publicKey) {
        $ec = new EC('secp256k1');
        $private_key = $ec->keyFromPrivate($privateKey, 'hex');
        $public_key = $ec->keyFromPublic($publicKey, 'hex');
        
        $ecies = new ECIES($private_key, $public_key);
        $decryptedText = $ecies->decrypt(hex2bin($cipher));

        return $decryptedText;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $action = $_POST['action'];

        if ($action === 'encrypt') {
            $message = $_POST['message'];
            $publicKey = $_POST['publicKey'];
            $privateKey = $_POST['privateKey'];
            $encrypted = encrypt($message, $privateKey, $publicKey);
            echo json_encode(['encrypted' => $encrypted]);
        } elseif ($action === 'decrypt') {
            $encrypted = $_POST['encrypted'];
            $privateKey = $_POST['privateKey'];
            $publicKey = $_POST['publicKey'];
            $decrypted = decrypt($encrypted, $privateKey, $publicKey);
            echo json_encode(['decrypted' => $decrypted]);
        }
    } elseif ($_SERVER['REQUEST_METHOD'] === 'GET' && $_GET['action'] === 'generateKeysPHP') {
        $keys = generateKeysPHP();
        echo json_encode(['publicKey' => $keys['publicKey'], 'privateKey' => $keys['privateKey']]);
    }
?>