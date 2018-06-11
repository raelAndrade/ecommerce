<?php

namespace Hcode\Model;

use \Hcode\DB\Sql;
use \Hcode\Mailer;
use \Hcode\Model;

class User extends Model{

  const SESSION = "User";
  const FORGOT_SECRET = "HcodePHP7_Secret";
  const ERROR = "UserError";
  const ERROR_REGISTER = "UserErrorRegister";

  public static function getFromSession()
  {
    $user = new User();
    if (isset($_SESSION[User::SESSION]) && (int)$_SESSION[User::SESSION]['iduser'] > 0) {
      $user->setData($_SESSION[User::SESSION]);
    }
    return $user;
  }

  public static function checkLogin($inadmin = true)
  {
    if(
       !isset($_SESSION[User::SESSION]) // se a sessão do usuario não for definida, quer dizer que ele não está logado
       ||
       !$_SESSION[User::SESSION] // se a sessão estiver vazia, tb não está logado
       ||
       !(int)$_SESSION[User::SESSION]["iduser"] > 0 // se a sessão está definida e não for vazia, mas o iduser não é maior que 0, significa que tb não está logado
     ) {
       // Não está logado
       return false; // então retorna false
     } else { // senão
       if ($inadmin === true && (bool)$_SESSION[User::SESSION]['inadmin'] === true) {
         // se o inadmin é igual a true e o boolean da sessão do inadim for igual a true
         return true; // retorna true
       } else if ($inadmin === false) { // se essa rota não é da administração for igual a false
         return true; // retorna a true
       } else { // se algo for diferente de disso, logo não está logado
         return false; // pede para o usuario fazer a autenticação
       }
     }

  }

  public static function login( $login, $password ){
       $sql = new Sql();
       $results = $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b ON a.idperson = b.idperson WHERE a.deslogin = :LOGIN", array(
       ":LOGIN" => $login
       ) );
       if (count($results) === 0){
           throw new \Exception ("Usuário inexistente ou senha inválida.");
       }
       $data = $results[0];
       if ( password_verify( $password, $data[ "despassword" ] ) === true ){
           $user = new User();
           $data['desperson'] = utf8_encode($data['desperson']);
           $user->setData( $data );
           $_SESSION[ User::SESSION ] = $user->getValues();
           return $user;
       } else {
           throw new \Exception ("Usuário inexistente ou senha inválida.");
       }
   }

   public static function verifyLogin($inadmin = true)
   {
     if (!User::checkLogin($inadmin)) {
       if ($inadmin) {
         header( "Location: /admin/login" );
       } else {
          header( "Location: /login" );
       }
       exit;
    }
  }

  public static function logout()
  {
    $_SESSION[User::SESSION] = NULL;
  }

  public static function listAll()
  {
    $sql = new Sql();
    return $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b USING(idperson) ORDER BY b.desperson");
  }

  public function save()
  {
      $sql = new Sql();
      $results = $sql->select("CALL sp_users_save(:desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)", array(
        ":desperson"=>utf8_decode($this->getdesperson()),
        ":deslogin"=>$this->getdeslogin(),
        ":despassword"=>User::getPasswordHash($this->getdespassword()),
        ":desemail"=>$this->getdesemail(),
        ":nrphone"=>$this->getnrphone(),
        ":inadmin"=>$this->getinadmin()
      ));
      $this->setData($results[0]);
  }

  public function get($iduser)
  {
    $sql = new Sql();
    $results = $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b USING(idperson) WHERE a.iduser = :iduser", array(
      ":iduser"=>$iduser
    ));

    $data = $results[0];
    $data['desperson'] = utf8_encode($data['desperson']);
    $this->setData($data);
  }

  public function update()
  {
    $sql = new Sql();
    $results = $sql->select("CALL sp_usersupdate_save(:iduser, :desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)", array(
      ":iduser"=>$this->getiduser(),
      ":desperson"=>utf8_decode($this->getdesperson()),
      ":deslogin"=>$this->getdeslogin(),
      ":despassword"=>User:getPasswordHash($this->getdespassword()),
      ":desemail"=>$this->getdesemail(),
      ":nrphone"=>$this->getnrphone(),
      ":inadmin"=>$this->getinadmin()
    ));
    $this->setData($results[0]);
  }

  public function delete()
  {
    $sql = new Sql();
    $sql->query("CALL sp_users_delete(:iduser)", array(
      ":iduser"=>$this->getiduser()
    ));
  }

  public function getForgot($email, $admin = true)
  {
    $sql = new Sql();
    $results = $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b USING(idperson) WHERE b.desemail = :desemail", array(
      ":desemail"=>$email
    ));

    if(count($results) > 0)
    {
      $data = $results[0];
			$results2 = $sql->select("CALL sp_userspasswordsrecoveries_create(:iduser, :desip)", array(
				":iduser"=>$data['iduser'],
				":desip"=>$_SERVER["REMOTE_ADDR"]
      ));
      $recoveryData = $results2[0];
			$encrypt = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, User::FORGOT_SECRET, $recoveryData['idrecovery'], MCRYPT_MODE_ECB);
      $encryptCode = base64_encode($encrypt);

      if ($admin === true) {
				$link = "http://www.hcodecommerce.com.br/admin/forgot/reset?code=";
			} else {
				$link = "http://www.hcodecommerce.com.br/forgot/reset?code=";
      }

      $mailer = new Mailer(
        $email,
				$data['desperson'],
				"Redefinição de senha da Hcode Store",
				"forgot",
			  array(
          "name"=>$data['desperson'],
          "link"=>$link.$encryptCode
      ));
			return $mailer->send();
		}else{
        throw new \Exception("Não foi possível redefinir a senha.");
    }
  }

  public static function validForgotDecrypt($code)
  {
    $code = trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_128, User::FORGOT_SECRET, base64_decode($code), MCRYPT_MODE_ECB));
    $sql = new Sql();
    $results = $sql->select("SELECT * FROM tb_userspasswordsrecoveries a INNER JOIN tb_users b USING(iduser) INNER JOIN tb_persons c USING(idperson)
  			WHERE
  			a.idrecovery = :idrecovery
  			AND
  			a.dtrecovery IS NULL
  			AND
  			DATE_ADD(a.dtregister, INTERVAL 1 HOUR) >= NOW();", array(
  			":idrecovery"=>$code
    ));

  	if (count($results) === 0)
  	{
  	   throw new \Exception("Recuperação inválida.");
  	}else{
      return $results[0];
  	}
  }

  public static function setForgotUsed($idrecovery)
  {
    $sql = new Sql();
    $sql->query("UPDATE tb_userspasswordsrecoveries SET dtrecovery = NOW() WHERE idrecovery = :idrecovery", array(
       ":idrecovery"=>$idrecovery
    ));
  }

  public function setPassword($password)
  {
    $sql = new Sql();
    $sql->query("UPDATE tb_users SET despassword = :password WHERE iduser = :iduser", array(
       ":password"=>$password,
       ":iduser"=>$this->getiduser()
    ));
  }

  public static function setError($msg)
  {
    $_SESSIO[User::ERROR] = $msg;
  }

  public static function getError()
  {
    $msg = (isset($_SESSION[User::ERROR]) && $_SESSION[User::ERROR]) ? $_SESSION[User::ERROR] : '';
    User::clearError();
    return $msg;
  }

  public static function clearError()
  {
    $_SESSION[User::ERROR] = NULL;
  }

  public static function setErrorRegister()
  {
    $_SESSION[User::ERROR_REGISTER] = $msg;
  }

  public static function checkLoginExist($login)
  {
    $sql = new Sql();
    $results = $sql->select("SELECT * FROM tb_users WHERE deslogin = :deslogin", [
      ':deslogin'=>$login
    ]);
    return (count($results) > 0);
  }

  public static function getPasswordHash($password)
  {
    return password_hash($password, PASSWORD_DEFAULT, [
      'cost'=>12
    ]);
  }

}

?>
