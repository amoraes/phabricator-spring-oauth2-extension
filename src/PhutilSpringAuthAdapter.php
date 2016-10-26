<?php

/**
 * Authentication adapter for Srpring OAuth2 Server.
 */
final class PhutilSpringAuthAdapter extends PhutilOAuthAuthAdapter {



  public function getAdapterType() {
    return 'spring';
  }

  public function getAdapterDomain() {
    return 'your.domain.com';
  }

  public function getAccountID() {
    return $this->getOAuthAccountData('name');
  }

  public function getAccountEmail() {
    return null;
  }

  public function getAccountName() {
    return $this->getOAuthAccountData('name');
  }

  public function getAccountImageURI() {
    return null;
  }

  public function getAccountURI() {
    return null;
  }

  public function getAccountRealName() {
    return $this->getOAuthAccountData('name');
  }

  protected function getAuthenticateBaseURI() {
    return 'https://'.$this->getAdapterDomain().'/oauth/authorize';
  }

  protected function getTokenBaseURI() {
    return 'https://'.$this->getAdapterDomain().'/oauth/token';
  }

  protected function loadOAuthAccountData() {
    $uri = new PhutilURI('https://'.$this->getAdapterDomain().'/user');
    #$uri->setQueryParam('access_token', $this->getAccessToken());

    $future = new HTTPSFuture($uri);

    $future->addHeader('Authorization', 'Bearer '.$this->getAccessToken());

    list($body) = $future->resolvex();

    try{
      return phutil_json_decode($body);
    } catch (PhutilJSONParserException $ex) {
      throw new PhutilProxyException(
        pht('Expected valid JSON response from GitHub account data request.'),
        $ex);
    }
  }
  
  //overwrite
  public function getAuthenticateURI() {
    $uri = new PhutilURI($this->getAuthenticateBaseURI());
    $uri->setQueryParam('client_id', $this->getClientID());
    $uri->setQueryParam('scope', $this->getScope());
    $uri->setQueryParam('redirect_uri', $this->getRedirectURI());
    $uri->setQueryParam('state', $this->getState());
    $uri->setQueryParam('response_type', 'code');
    foreach ($this->getExtraAuthenticateParameters() as $key => $value) {
      $uri->setQueryParam($key, $value);
    }
    return (string)$uri;
  }

  protected function loadAccessTokenData() {
    $code = $this->getCode();
    if (!$code) {
      throw new PhutilInvalidStateException('setCode');
    }
    $params = array(
      'code' => $this->getCode(),
    ) + $this->getExtraTokenParameters();
    return $this->makeTokenRequest($params);
  }

  private function makeTokenRequest(array $params) {
    $uri = $this->getTokenBaseURI();
    $query_data = array(
      'client_id'       => $this->getClientID(),
      'client_secret'   => $this->getClientSecret()->openEnvelope(),
      'redirect_uri'    => $this->getRedirectURI(),
      'grant_type'      => 'authorization_code'
    ) + $params;
    $future = new HTTPSFuture($uri, $query_data);
    $future->setMethod('POST');
    $future->addHeader('Authorization','Basic '.base64_encode($this->getClientID().":".$this->getClientSecret()->openEnvelope()));
    list($body) = $future->resolvex();
    $data = $this->readAccessTokenResponse($body);
    if (isset($data['expires_in'])) {
      $data['expires_epoch'] = $data['expires_in'];
    } else if (isset($data['expires'])) {
      $data['expires_epoch'] = $data['expires'];
    }
    // If we got some "expires" value back, interpret it as an epoch timestamp
    // if it's after the year 2010 and as a relative number of seconds
    // otherwise.
    if (isset($data['expires_epoch'])) {
      if ($data['expires_epoch'] < (60 * 60 * 24 * 365 * 40)) {
        $data['expires_epoch'] += time();
      }
    }
    if (isset($data['error'])) {
      throw new Exception(pht('Access token error: %s', $data['error']));
    }
    return $data;
  }

}
               
