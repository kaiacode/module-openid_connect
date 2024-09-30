<?php

namespace Drupal\vdm_openid_connect\Plugin\OpenIDConnectClient;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\Url;
use Drupal\openid_connect\Plugin\OpenIDConnectClientBase;
use Exception;

/**
 * Okta OpenID Connect client.
 *
 * Implements OpenID Connect Client plugin for Okta.
 *
 * @OpenIDConnectClient(
 *   id = "vdmgcsauth",
 *   label = @Translation("VDM Azure")
 * )
 */
class OpenIDConnectVDMClient extends OpenIDConnectClientBase {


  /**
   * {@inheritdoc}
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state): array {
    $form = parent::buildConfigurationForm($form, $form_state);

    $form['client_id'] = [
      '#title' => $this->t("Client ID (donnée provenant des variables d'environnement)"),
      '#type' => 'textfield',
      '#default_value' => $this->getClientId(),
      '#attributes' => ['readonly' => 'readonly'],
    ];

    $form['client_secret'] = [
      '#title' => $this->t("Client secret (donnée provenant des variables d'environnement)"),
      '#type' => 'textfield',
      '#default_value' => $this->getClientSecret(),
      '#attributes' => ['readonly' => 'readonly'],
    ];

    $form['authorization_endpoint'] = [
      '#title' => $this->t("Authorization endpoint (donnée provenant des variables d'environnement)"),
      '#type' => 'textfield',
      '#default_value' => $this->getAuthorizationEndpoint(),
      '#attributes' => ['readonly' => 'readonly'],
    ];

    $form['token_endpoint'] = [
      '#title' => $this->t("Token endpoint (donnée provenant des variables d'environnement)"),
      '#type' => 'textfield',
      '#default_value' => $this->getTokenEndpoint(),
      '#attributes' => ['readonly' => 'readonly'],
    ];

    $form['scope'] = [
      '#title' => $this->t('Scope claim'),
      '#description' => $this->t('Parameters are separated by space character.'),
      '#type' => 'textfield',
      '#default_value' => $this->getScope(),
    ];

    $form['response_type'] = [
      '#title' => $this->t('Response type'),
      '#description' => $this->t('Response Type value that determines the authorization processing flow to be used.'),
      '#type' => 'textfield',
      '#default_value' => $this->getResponseType(),
    ];

    $form['grant_type'] = [
      '#title' => $this->t('Grant type'),
      '#description' => $this->t('Grant Types that the Client is declaring that it will restrict itself to using.'),
      '#type' => 'textfield',
      '#default_value' => $this->getGrantType(),
    ];

    return $form;
  }


  /**
   * Implements OpenIDConnectClientInterface::authorize().
   *
   * @param string $scope
   *   A string of scopes.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   A trusted redirect response object.
   */
  public function authorize($scope = 'openid email') {
    $language = \Drupal::languageManager()->getCurrentLanguage();
    $redirect_uri = Url::fromRoute(
      'openid_connect.redirect_controller_redirect',
      [
        'client_name' => $this->pluginId,
      ],
      [
        'absolute' => TRUE,
        'language' => $language,
        'https' => getenv('ENV') !== 'local',
      ]
    )->toString(TRUE);
    $endpoints = $this->getEndpoints();

    $url_options = [
      'query' => [
        'client_id' => $this->getClientId(),
        'response_type' => $this->getResponseType(),
        'scope' => $this->getScope(),
        'ui_locales' => $language->getId(),
        'grant_type' => $this->getGrantType(),
        'redirect_uri' => $redirect_uri->getGeneratedUrl(),
        'state' => \Drupal::service('openid_connect.state_token')->create(),
      ],
    ];

    // Clear _GET['destination'] because we need to override it.
    $this->requestStack->getCurrentRequest()->query->remove('destination');
    $authorization_endpoint = Url::fromUri($endpoints['authorization'], $url_options)
      ->toString(TRUE);

    $response = new TrustedRedirectResponse($authorization_endpoint->getGeneratedUrl());
    // We can't cache the response, since this will prevent the state to be
    // added to the session. The kill switch will prevent the page getting
    // cached for anonymous users when page cache is active.
    \Drupal::service('page_cache_kill_switch')->trigger();

    return $response;
  }

  /**
   * Implements OpenIDConnectClientInterface::retrieveIDToken().
   *
   * @param string $authorization_code
   *   A authorization code string.
   *
   * @return array|bool
   *   A result array or false.
   */
  public function retrieveTokens($authorization_code) {
    $language = \Drupal::languageManager()->getCurrentLanguage();
    $redirect_uri = Url::fromRoute(
      'openid_connect.redirect_controller_redirect',
      [
        'client_name' => $this->pluginId,
      ],
      [
        'absolute' => TRUE,
        'language' => $language,
        'https' => getenv('ENV') !== 'local',
      ]
    )->toString();
    $endpoints = $this->getEndpoints();

    $request_options = [
      'form_params' => [
        'code' => $authorization_code,
        'client_id' => $this->getClientId(),
        'client_secret' => $this->getClientSecret(),
        'redirect_uri' => $redirect_uri,
        'grant_type' => $this->getGrantType(),
      ],
      'headers' => [
        'Accept' => 'application/json',
      ],
    ];

    /* @var \GuzzleHttp\ClientInterface $client */
    $client = $this->httpClient;
    try {
      $response = $client->post($endpoints['token'], $request_options);
      $response_data = json_decode((string) $response->getBody(), TRUE);

      // Expected result.
      $tokens = [
        'id_token' => isset($response_data['id_token']) ? $response_data['id_token'] : NULL,
        'access_token' => isset($response_data['access_token']) ? $response_data['access_token'] : NULL,
      ];
      if (array_key_exists('expires_in', $response_data)) {
        $tokens['expire'] = \Drupal::time()
            ->getRequestTime() + $response_data['expires_in'];
      }
      if (array_key_exists('refresh_token', $response_data)) {
        $tokens['refresh_token'] = $response_data['refresh_token'];
      }
      return $tokens;
    } catch (Exception $e) {
      $variables = [
        '@message' => 'Could not retrieve tokens',
        '@error_message' => $e->getMessage(),
      ];
      $this->loggerFactory->get('openid_connect_' . $this->pluginId)
        ->error('@message. Details: @error_message', $variables);
      return FALSE;
    }
  }

  /**
   * Implements OpenIDConnectClientInterface::retrieveUserInfo().
   *
   * @param string $access_token
   *   An access token string.
   *
   * @return array|bool
   *   A result array or false.
   */
  public function retrieveUserInfo($access_token) {
    [$header, $body, $signature] = explode('.', $access_token);
    $header = base64_decode($header);
    $body = (array) json_decode(base64_decode($body));
    $signature = base64_decode($signature);
    if (empty($body)) {
      return FALSE;
    }
    $body['email'] = $body['email'] ?? $body['preferred_username'];
    return $body;
  }


  /**
   * @return string
   */
  public function getScope() {
    return "openid profile email " . $this->getClientId() . "/.default";
  }

  /**
   * @return string
   */
  public function getClientId(): string {
    return getenv('OPENID_CLIENT_ID') ? getenv('OPENID_CLIENT_ID') : '';
  }

  /**
   * @return string
   */
  public function getClientSecret(): string {
    return getenv('OPENID_CLIENT_SECRET') ? getenv('OPENID_CLIENT_SECRET') : '';
  }

  /**
   * @return string
   */
  public function getAuthorizationEndpoint(): string {
    return getenv('OPENID_AUTHORIZATION_ENDPOINT') ? getenv('OPENID_AUTHORIZATION_ENDPOINT') : '';
  }

  /**
   * @return string
   */
  public function getTokenEndpoint(): string {
    return getenv('OPENID_TOKEN_ENDPOINT') ? getenv('OPENID_TOKEN_ENDPOINT') : '';
  }

  /**
   * {@inheritdoc}
   */
  public function getResponseType() {
    return getenv('OPENID_RESPONSE_TYPE') ? getenv('OPENID_RESPONSE_TYPE') : 'code';
  }

  /**
   * {@inheritdoc}
   */
  public function getGrantType() {
    return getenv('OPENID_GRANT_TYPE') ? getenv('OPENID_GRANT_TYPE') : 'authorization_code';
  }

  /**
   * {@inheritdoc}
   */
  public function getEndpoints(): array {
    return [
      'authorization' => $this->getAuthorizationEndpoint(),
      'token' => $this->getTokenEndpoint(),
    ];
  }

}
