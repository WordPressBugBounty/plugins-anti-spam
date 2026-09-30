<?php
/**
 * Abilities API integration.
 *
 * Registers Titan Security abilities as thin wrappers over the REST controller,
 * the audit and the vulnerabilities services.
 *
 * @package Titan_Security
 */

namespace WBCR\Titan;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Titan_Abilities Class
 */
class Titan_Abilities {

	/**
	 * Ability category slug.
	 */
	private const CATEGORY = 'titan-security';

	/**
	 * Maximum page size for list abilities.
	 */
	private const MAX_PER_PAGE = 100;

	/**
	 * Protection switches.
	 */
	private const POLICY_SWITCHES = [
		'antispam_mode',
		'advanced_spam_filter',
		'strong_password',
		'protect_author_get',
		'remove_x_pingback',
		'remove_html_comments',
		'remove_meta_generator',
		'remove_js_version',
		'remove_style_version',
		'bruteforce_enabled',
	];

	/**
	 * Protection settings that only work with an active Pro license.
	 */
	private const POLICY_PRO_FIELDS = [ 'advanced_spam_filter' ];

	/**
	 * Roles accepted by the strong password policy, the same options as the settings endpoint.
	 */
	private const POLICY_ROLES = [ 'administrator', 'editor', 'author', 'contributor', 'subscriber' ];

	/**
	 * Integer policy fields with the bounds enforced by the settings endpoint.
	 */
	private const POLICY_INTEGERS = [
		'bruteforce_allowed_retries' => [ 1, 100 ],
		'bruteforce_minutes_lockout' => [ 60, 86400 ],
		'bruteforce_valid_duration'  => [ 3600, 604800 ],
	];

	/**
	 * List policy fields.
	 */
	private const POLICY_LISTS = [
		'bruteforce_whitelist_ips',
		'bruteforce_whitelist_usernames',
		'bruteforce_blacklist_ips',
		'bruteforce_blacklist_usernames',
	];

	/**
	 * Hook the registration callbacks.
	 *
	 * @return void
	 */
	public static function init(): void {
		add_action( 'wp_abilities_api_categories_init', [ __CLASS__, 'register_category' ] );
		add_action( 'wp_abilities_api_init', [ __CLASS__, 'register_abilities' ] );
	}

	/**
	 * Register the ability category.
	 *
	 * @return void
	 */
	public static function register_category(): void {
		if ( ! function_exists( 'wp_register_ability_category' ) ) {
			return;
		}

		wp_register_ability_category(
			self::CATEGORY,
			[
				'label'       => __( 'Titan Security', 'anti-spam' ),
				'description' => __( 'Security findings, protection rules, blocked clients and backups managed by Titan Security.', 'anti-spam' ),
			]
		);
	}

	/**
	 * Register the abilities.
	 *
	 * @return void
	 */
	public static function register_abilities(): void {
		if ( ! function_exists( 'wp_register_ability' ) ) {
			return;
		}

		foreach ( self::get_definitions() as $name => $definition ) {
			$annotations = $definition['annotations'];
			unset( $definition['annotations'] );

			$definition['category']            = self::CATEGORY;
			$definition['permission_callback'] = [ __CLASS__, 'check_permissions' ];
			$definition['meta']                = [
				'annotations'  => $annotations,
				'show_in_rest' => true,
			];

			if ( isset( $definition['task'] ) ) {
				$definition['meta']['task'] = $definition['task'];
				unset( $definition['task'] );
			}

			// Left out of the SDK's "Connect your AI agent" enable list.
			if ( array_key_exists( 'ai_connect', $definition ) ) {
				$definition['meta']['ai_connect'] = (bool) $definition['ai_connect'];
				unset( $definition['ai_connect'] );
			}

			wp_register_ability( $name, $definition );
		}
	}

	/**
	 * Permission check, the same one used by the dashboard REST routes.
	 *
	 * @return bool
	 */
	public static function check_permissions(): bool {
		return Titan_Rest_Controller::get_instance()->check_permissions();
	}

	/**
	 * Ability definitions.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private static function get_definitions(): array {
		$pagination = [
			'page'     => [
				'type'        => 'integer',
				'description' => __( 'Page number, starting at 1.', 'anti-spam' ),
				'minimum'     => 1,
				'default'     => 1,
			],
			'per_page' => [
				'type'        => 'integer',
				'description' => __( 'Items per page (max 100).', 'anti-spam' ),
				'minimum'     => 1,
				'maximum'     => self::MAX_PER_PAGE,
				'default'     => 20,
			],
		];

		$policy_properties = self::get_policy_properties();

		return [
			'titan/get-security-findings'    => [
				'label'            => __( 'Get security findings', 'anti-spam' ),
				'description'      => __( 'Returns the security audit issues and the known vulnerabilities detected for WordPress core, plugins and themes. Vulnerability findings require an active Pro license.', 'anti-spam' ),
				'input_schema'     => [
					'type'                 => 'object',
					'properties'           => array_merge(
						[
							'source'         => [
								'type'        => 'string',
								'description' => __( 'Which findings to return.', 'anti-spam' ),
								'enum'        => [ 'all', 'audit', 'vulnerability' ],
								'default'     => 'all',
							],
							'severity'       => [
								'type'        => 'string',
								'description' => __( 'Only return audit findings with this severity. Vulnerability findings have no severity and are left out when this is set.', 'anti-spam' ),
								'enum'        => [ 'low', 'medium', 'high' ],
							],
							'include_hidden' => [
								'type'        => 'boolean',
								'description' => __( 'Include audit findings hidden from the dashboard.', 'anti-spam' ),
								'default'     => false,
							],
						],
						$pagination
					),
					'additionalProperties' => false,
				],
				'output_schema'    => [
					'type'       => 'object',
					'properties' => [
						'findings'                 => [
							'type'  => 'array',
							'items' => [ 'type' => 'object' ],
						],
						'total'                    => [ 'type' => 'integer' ],
						'page'                     => [ 'type' => 'integer' ],
						'per_page'                 => [ 'type' => 'integer' ],
						'vulnerabilities_included' => [ 'type' => 'boolean' ],
					],
				],
				'execute_callback' => [ __CLASS__, 'get_security_findings' ],
				'annotations'      => [
					'readonly'    => true,
					'destructive' => false,
					'idempotent'  => true,
				],
			],
			'titan/get-protection-policy'    => [
				'label'            => __( 'Get protection policy', 'anti-spam' ),
				'description'      => __( 'Returns the current protection rules: anti-spam, brute-force limits and lists, strong passwords and hardening tweaks.', 'anti-spam' ),
				'output_schema'    => [
					'type'       => 'object',
					'properties' => [
						'policy'     => [
							'type'       => 'object',
							'properties' => $policy_properties,
						],
						'pro_active' => [ 'type' => 'boolean' ],
					],
				],
				'execute_callback' => [ __CLASS__, 'get_protection_policy' ],
				'annotations'      => [
					'readonly'    => true,
					'destructive' => false,
					'idempotent'  => true,
				],
			],
			'titan/update-protection-policy' => [
				'label'            => __( 'Update protection policy', 'anti-spam' ),
				'description'      => __( 'Updates protection rules with the same rules as the plugin settings screen: switches can be turned on or off, which can weaken protection, and limits must stay within the supported bounds. Only the provided fields change.', 'anti-spam' ),
				'input_schema'     => [
					'type'                 => 'object',
					'properties'           => array_merge(
						$policy_properties,
						[
							'dry_run' => [
								'type'        => 'boolean',
								'description' => __( 'Validate and return the resulting policy without saving.', 'anti-spam' ),
								'default'     => false,
							],
						]
					),
					'additionalProperties' => false,
				],
				'output_schema'    => [
					'type'       => 'object',
					'properties' => [
						'updated' => [
							'type'  => 'array',
							'items' => [ 'type' => 'string' ],
						],
						'dry_run' => [ 'type' => 'boolean' ],
						'policy'  => [
							'type'       => 'object',
							'properties' => $policy_properties,
						],
					],
				],
				'execute_callback' => [ __CLASS__, 'update_protection_policy' ],
				'ai_connect'       => false,
				'annotations'      => [
					'readonly'    => false,
					'destructive' => true,
					'idempotent'  => true,
				],
			],
			'titan/list-blocked-clients'     => [
				'label'            => __( 'List blocked clients', 'anti-spam' ),
				'description'      => __( 'Lists the brute-force lockout log: IP address, username, failed attempts and whether the client is currently locked out. Contains personal data.', 'anti-spam' ),
				'input_schema'     => [
					'type'                 => 'object',
					'properties'           => array_merge(
						[
							'ip'          => [
								'type'        => 'string',
								'description' => __( 'Only return records for this IP address.', 'anti-spam' ),
							],
							'username'    => [
								'type'        => 'string',
								'description' => __( 'Only return records for this username.', 'anti-spam' ),
							],
							'only_locked' => [
								'type'        => 'boolean',
								'description' => __( 'Only return clients that are locked out right now.', 'anti-spam' ),
								'default'     => false,
							],
						],
						$pagination
					),
					'additionalProperties' => false,
				],
				'output_schema'    => [
					'type'       => 'object',
					'properties' => [
						'clients'  => [
							'type'  => 'array',
							'items' => [
								'type'       => 'object',
								'properties' => [
									'ip'        => [ 'type' => 'string' ],
									'username'  => [ 'type' => 'string' ],
									'date'      => [ 'type' => 'string' ],
									'attempts'  => [ 'type' => 'integer' ],
									'gateway'   => [ 'type' => 'string' ],
									'is_locked' => [ 'type' => 'boolean' ],
									'unlocked'  => [ 'type' => 'boolean' ],
								],
							],
						],
						'total'    => [ 'type' => 'integer' ],
						'page'     => [ 'type' => 'integer' ],
						'per_page' => [ 'type' => 'integer' ],
					],
				],
				'execute_callback' => [ __CLASS__, 'list_blocked_clients' ],
				'annotations'      => [
					'readonly'    => true,
					'destructive' => false,
					'idempotent'  => true,
				],
			],
			'titan/unblock-client'           => [
				'label'            => __( 'Unblock client', 'anti-spam' ),
				'description'      => __( 'Removes the brute-force lockout of a single IP address and marks its log records as unlocked.', 'anti-spam' ),
				'input_schema'     => [
					'type'                 => 'object',
					'properties'           => [
						'ip' => [
							'type'        => 'string',
							'description' => __( 'The IP address to unlock, as returned by titan/list-blocked-clients.', 'anti-spam' ),
						],
					],
					'required'             => [ 'ip' ],
					'additionalProperties' => false,
				],
				'output_schema'    => [
					'type'       => 'object',
					'properties' => [
						'ip'         => [ 'type' => 'string' ],
						'was_locked' => [ 'type' => 'boolean' ],
						'message'    => [ 'type' => 'string' ],
					],
				],
				'execute_callback' => [ __CLASS__, 'unblock_client' ],
				'annotations'      => [
					'readonly'    => false,
					'destructive' => true,
					'idempotent'  => true,
				],
			],
			'titan/start-backup'             => [
				'label'            => __( 'Start backup', 'anti-spam' ),
				'description'      => __( 'Starts a site backup using the configured storage. The backup runs in the background and a job_id is returned: call titan/list-backups with that job_id to follow progress until state is no longer working. Requires Pro.', 'anti-spam' ),
				'output_schema'    => [
					'type'       => 'object',
					'properties' => [
						'job_id'  => [
							'type'        => 'string',
							'description' => __( 'Reference of this backup. Pass it to titan/list-backups as job_id.', 'anti-spam' ),
						],
						'status'  => [ 'type' => 'string' ],
						'storage' => [ 'type' => 'string' ],
						'message' => [ 'type' => 'string' ],
					],
				],
				'execute_callback' => [ __CLASS__, 'start_backup' ],
				'annotations'      => [
					'readonly'    => false,
					'destructive' => true,
					'idempotent'  => false,
				],
				'task'             => [
					'mode'           => 'poll',
					'status_ability' => 'titan/list-backups',
				],
			],
			'titan/list-backups'             => [
				'label'            => __( 'List backups', 'anti-spam' ),
				'description'      => __( 'Lists existing backups with size, storage and status, including the progress of a running backup. Pass the job_id returned by titan/start-backup to get the state and progress of that backup. Requires Pro.', 'anti-spam' ),
				'input_schema'     => [
					'type'                 => 'object',
					'properties'           => array_merge(
						[
							'job_id' => [
								'type'        => 'string',
								'description' => __( 'Backup id returned by titan/start-backup. When set, only that backup is listed and state and progress are returned.', 'anti-spam' ),
							],
						],
						$pagination
					),
					'additionalProperties' => false,
				],
				'output_schema'    => [
					'type'       => 'object',
					'properties' => [
						'backups'       => [
							'type'  => 'array',
							'items' => [
								'type'       => 'object',
								'properties' => [
									'id'       => [ 'type' => 'string' ],
									'size'     => [ 'type' => 'string' ],
									'storage'  => [ 'type' => 'string' ],
									'status'   => [ 'type' => 'string' ],
									'progress' => [ 'type' => 'number' ],
								],
							],
						],
						'backup_status' => [ 'type' => 'string' ],
						'job_id'        => [ 'type' => 'string' ],
						'state'         => [
							'type' => 'string',
							'enum' => [ 'working', 'completed', 'failed', 'cancelled' ],
						],
						'progress'      => [
							'type'       => 'object',
							'properties' => [
								'current' => [ 'type' => 'integer' ],
								'total'   => [ 'type' => 'integer' ],
								'message' => [ 'type' => 'string' ],
							],
						],
						'total'         => [ 'type' => 'integer' ],
						'page'          => [ 'type' => 'integer' ],
						'per_page'      => [ 'type' => 'integer' ],
					],
				],
				'execute_callback' => [ __CLASS__, 'list_backups' ],
				'annotations'      => [
					'readonly'    => true,
					'destructive' => false,
					'idempotent'  => true,
				],
			],
		];
	}

	/**
	 * JSON schema properties of the protection policy.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private static function get_policy_properties(): array {
		$properties = [];

		foreach ( self::POLICY_SWITCHES as $key ) {
			$properties[ $key ] = [ 'type' => 'boolean' ];
		}

		$properties['strong_password_min_role'] = [
			'type'        => 'string',
			'description' => __( 'Minimum role at which a user must choose a strong password.', 'anti-spam' ),
			'enum'        => self::POLICY_ROLES,
		];

		foreach ( self::POLICY_INTEGERS as $key => $bounds ) {
			$properties[ $key ] = [
				'type'    => 'integer',
				'minimum' => $bounds[0],
				'maximum' => $bounds[1],
			];
		}

		foreach ( self::POLICY_LISTS as $key ) {
			$properties[ $key ] = [
				'type'  => 'array',
				'items' => [ 'type' => 'string' ],
			];
		}

		return $properties;
	}

	/**
	 * Normalize the ability input.
	 *
	 * @param mixed $input Raw input.
	 *
	 * @return array<string, mixed>
	 */
	private static function normalize_input( $input ): array {
		if ( is_object( $input ) ) {
			$input = (array) $input;
		}

		return is_array( $input ) ? $input : [];
	}

	/**
	 * Run one of the plugin's own REST routes, with its permission, validation and sanitization callbacks.
	 *
	 * @param string               $route  Route to dispatch.
	 * @param array<string, mixed> $params Request parameters.
	 *
	 * @return true|\WP_Error
	 */
	private static function dispatch( string $route, array $params ) {
		$request = new \WP_REST_Request( 'POST', $route );

		foreach ( $params as $key => $value ) {
			$request->set_param( $key, $value );
		}

		$response = rest_do_request( $request );

		if ( $response->is_error() ) {
			$error = $response->as_error();

			return $error instanceof \WP_Error ? $error : new \WP_Error( 'titan_request_failed', __( 'The request could not be completed.', 'anti-spam' ) );
		}

		return true;
	}

	/**
	 * Slice a list of items according to the pagination input.
	 *
	 * @param array<int, mixed>    $items Items.
	 * @param array<string, mixed> $input Ability input.
	 *
	 * @return array{items: array<int, mixed>, total: int, page: int, per_page: int}
	 */
	private static function paginate( array $items, array $input ): array {
		$page     = isset( $input['page'] ) ? max( 1, absint( $input['page'] ) ) : 1;
		$per_page = isset( $input['per_page'] ) ? absint( $input['per_page'] ) : 20;
		$per_page = min( self::MAX_PER_PAGE, max( 1, $per_page ) );

		return [
			'items'    => array_slice( $items, ( $page - 1 ) * $per_page, $per_page ),
			'total'    => count( $items ),
			'page'     => $page,
			'per_page' => $per_page,
		];
	}

	/**
	 * Get the security findings.
	 *
	 * @param mixed $input Ability input.
	 *
	 * @return array<string, mixed>
	 */
	public static function get_security_findings( $input = [] ): array {
		$input          = self::normalize_input( $input );
		$source         = isset( $input['source'] ) ? sanitize_key( (string) $input['source'] ) : 'all';
		$severity       = isset( $input['severity'] ) ? sanitize_key( (string) $input['severity'] ) : '';
		$include_hidden = ! empty( $input['include_hidden'] );
		$findings       = [];

		if ( 'vulnerability' !== $source ) {
			$findings = self::get_audit_findings( $severity, $include_hidden );
		}

		$is_premium = Plugin::app()->is_premium();

		if ( 'audit' !== $source && $is_premium && '' === $severity ) {
			$findings = array_merge( $findings, self::get_vulnerability_findings() );
		}

		$paged = self::paginate( $findings, $input );

		return [
			'findings'                 => $paged['items'],
			'total'                    => $paged['total'],
			'page'                     => $paged['page'],
			'per_page'                 => $paged['per_page'],
			'vulnerabilities_included' => 'audit' !== $source && $is_premium && '' === $severity,
		];
	}

	/**
	 * Audit findings, read the same way the dashboard does.
	 *
	 * @param string $severity       Severity filter.
	 * @param bool   $include_hidden Whether to include hidden items.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function get_audit_findings( string $severity, bool $include_hidden ): array {
		require_once WTITAN_PLUGIN_DIR . '/includes/audit/boot.php';

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$audit   = Audit::app();
		$results = $audit->get_audit();

		if ( false === $results || empty( $results ) ) {
			$results = $audit->do_audit();
		}

		if ( ! is_array( $results ) ) {
			return [];
		}

		$hidden_ids = get_option( 'titan_audit_hidden_items', [] );
		$hidden_ids = is_array( $hidden_ids ) ? array_map( 'strval', $hidden_ids ) : [];
		$findings   = [];

		foreach ( $results as $id => $item ) {
			$hidden = in_array( (string) $id, $hidden_ids, true );

			if ( $hidden && ! $include_hidden ) {
				continue;
			}

			if ( '' !== $severity && $severity !== $item->severity ) {
				continue;
			}

			$findings[] = [
				'id'          => 'audit-' . $id,
				'source'      => 'audit',
				'title'       => wp_strip_all_tags( (string) $item->title ),
				'description' => wp_strip_all_tags( (string) $item->description ),
				'severity'    => (string) $item->severity,
				'detected_at' => gmdate( 'c', (int) $item->timestamp ),
				'hidden'      => $hidden,
			];
		}

		return $findings;
	}

	/**
	 * Vulnerability findings from the vulnerabilities service.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function get_vulnerability_findings(): array {
		$findings = [];

		foreach ( Vulnerabilities::app()->get_vulnerability_data() as $slug => $software ) {
			if ( empty( $software['vulnerabilities'] ) || ! is_array( $software['vulnerabilities'] ) ) {
				continue;
			}

			foreach ( $software['vulnerabilities'] as $vulnerability ) {
				if ( ! is_array( $vulnerability ) ) {
					continue;
				}

				$affected = isset( $vulnerability['software'][0] ) && is_array( $vulnerability['software'][0] ) ? $vulnerability['software'][0] : [];
				$type     = 'wordpress' === $slug ? 'core' : 'plugin'; // phpcs:ignore WordPress.WP.CapitalPDangit.MisspelledInText

				if ( isset( $affected['type'] ) && is_string( $affected['type'] ) ) {
					$type = sanitize_key( $affected['type'] );
				}

				$patched_versions = [];
				if ( isset( $affected['patched_versions'] ) && is_array( $affected['patched_versions'] ) ) {
					$patched_versions = array_values( array_map( 'strval', $affected['patched_versions'] ) );
				}

				$findings[] = [
					'id'                => isset( $vulnerability['id'] ) ? (string) $vulnerability['id'] : '',
					'source'            => 'vulnerability',
					'title'             => isset( $vulnerability['title'] ) ? wp_strip_all_tags( (string) $vulnerability['title'] ) : '',
					'software'          => (string) $slug,
					'software_type'     => $type,
					'installed_version' => isset( $software['version'] ) ? (string) $software['version'] : '',
					'patched'           => ! empty( $affected['patched'] ),
					'patched_versions'  => $patched_versions,
					'published'         => isset( $vulnerability['published'] ) ? (string) $vulnerability['published'] : '',
				];
			}
		}

		return $findings;
	}

	/**
	 * Read the protection policy from the settings endpoint.
	 *
	 * @return array<string, mixed>
	 */
	private static function read_policy(): array {
		$data     = Titan_Rest_Controller::get_instance()->get_settings()->get_data();
		$settings = is_array( $data ) && isset( $data['settings'] ) && is_array( $data['settings'] ) ? $data['settings'] : [];

		// Only the allowlisted protection fields are exposed. Storage data and other settings never are.
		return array_intersect_key( $settings, self::get_policy_properties() );
	}

	/**
	 * Get the protection policy.
	 *
	 * @return array<string, mixed>
	 */
	public static function get_protection_policy(): array {
		return [
			'policy'     => self::read_policy(),
			'pro_active' => Plugin::app()->is_premium(),
		];
	}

	/**
	 * Update the protection policy.
	 *
	 * @param mixed $input Ability input.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function update_protection_policy( $input = [] ) {
		$input   = self::normalize_input( $input );
		$dry_run = ! empty( $input['dry_run'] );
		$changes = array_intersect_key( $input, self::get_policy_properties() );
		$unknown = array_diff( array_keys( $input ), array_keys( $changes ), [ 'dry_run' ] );

		if ( ! empty( $unknown ) ) {
			return new \WP_Error(
				'titan_policy_field_not_allowed',
				sprintf(
					// translators: %s: list of field names.
					__( 'These fields cannot be changed through this ability: %s', 'anti-spam' ),
					implode( ', ', array_map( 'sanitize_key', $unknown ) )
				),
				[ 'status' => 400 ]
			);
		}

		if ( empty( $changes ) ) {
			return new \WP_Error( 'titan_policy_empty', __( 'No settings data provided.', 'anti-spam' ), [ 'status' => 400 ] );
		}

		$current = self::read_policy();

		foreach ( $changes as $key => $value ) {
			if ( in_array( $key, self::POLICY_SWITCHES, true ) ) {
				if ( ! is_bool( $value ) ) {
					return new \WP_Error(
						'titan_policy_invalid_value',
						// translators: %s: setting name.
						sprintf( __( 'Setting %s must be a boolean.', 'anti-spam' ), $key ),
						[ 'status' => 400 ]
					);
				}
			}

			if ( in_array( $key, self::POLICY_PRO_FIELDS, true ) && ! Plugin::app()->is_premium() ) {
				return new \WP_Error(
					'titan_pro_required',
					// translators: %s: setting name.
					sprintf( __( 'Setting %s requires an active Titan Security Pro license.', 'anti-spam' ), $key ),
					[ 'status' => 403 ]
				);
			}

			if ( isset( self::POLICY_INTEGERS[ $key ] ) && ! is_int( $value ) ) {
				return new \WP_Error(
					'titan_policy_invalid_value',
					// translators: %s: setting name.
					sprintf( __( 'Setting %s must be a number.', 'anti-spam' ), $key ),
					[ 'status' => 400 ]
				);
			}

			if ( in_array( $key, self::POLICY_LISTS, true ) ) {
				if ( ! is_array( $value ) ) {
					return new \WP_Error(
						'titan_policy_invalid_value',
						// translators: %s: setting name.
						sprintf( __( 'Setting %s must be an array.', 'anti-spam' ), $key ),
						[ 'status' => 400 ]
					);
				}

				$changes[ $key ] = array_values( array_filter( $value, 'is_string' ) );
			}
		}

		// Same validation and sanitization as the settings endpoint.
		$controller = Titan_Rest_Controller::get_instance();
		$valid      = $controller->validate_settings( $changes );

		if ( is_wp_error( $valid ) ) {
			return $valid;
		}

		$sanitized = $controller->sanitize_settings( $changes );

		if ( $dry_run ) {
			return [
				'updated' => array_keys( $sanitized ),
				'dry_run' => true,
				'policy'  => array_merge( $current, $sanitized ),
			];
		}

		$response = self::dispatch( '/titan-security/v1/settings', [ 'data' => $sanitized ] );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		return [
			'updated' => array_keys( $sanitized ),
			'dry_run' => false,
			'policy'  => self::read_policy(),
		];
	}

	/**
	 * List blocked clients from the brute-force log.
	 *
	 * @param mixed $input Ability input.
	 *
	 * @return array<string, mixed>
	 */
	public static function list_blocked_clients( $input = [] ): array {
		$input       = self::normalize_input( $input );
		$ip          = isset( $input['ip'] ) ? sanitize_text_field( (string) $input['ip'] ) : '';
		$username    = isset( $input['username'] ) ? sanitize_user( (string) $input['username'] ) : '';
		$only_locked = ! empty( $input['only_locked'] );

		$data    = Titan_Rest_Controller::get_instance()->get_bruteforce_log()->get_data();
		$log     = is_array( $data ) && isset( $data['log'] ) && is_array( $data['log'] ) ? $data['log'] : [];
		$clients = [];

		foreach ( $log as $entry ) {
			if ( '' !== $ip && $ip !== $entry['ip'] ) {
				continue;
			}

			if ( '' !== $username && $username !== $entry['username'] ) {
				continue;
			}

			if ( $only_locked && empty( $entry['is_locked'] ) ) {
				continue;
			}

			$clients[] = [
				'ip'        => (string) $entry['ip'],
				'username'  => (string) $entry['username'],
				'date'      => gmdate( 'c', (int) $entry['date'] ),
				'attempts'  => (int) $entry['counter'],
				'gateway'   => (string) $entry['gateway'],
				'is_locked' => (bool) $entry['is_locked'],
				'unlocked'  => (bool) $entry['unlocked'],
			];
		}

		$paged = self::paginate( $clients, $input );

		return [
			'clients'  => $paged['items'],
			'total'    => $paged['total'],
			'page'     => $paged['page'],
			'per_page' => $paged['per_page'],
		];
	}

	/**
	 * Unblock a single client.
	 *
	 * @param mixed $input Ability input.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function unblock_client( $input = [] ) {
		$input = self::normalize_input( $input );
		$ip    = isset( $input['ip'] ) ? sanitize_text_field( (string) $input['ip'] ) : '';

		if ( '' === $ip ) {
			return new \WP_Error( 'titan_missing_ip', __( 'IP address is required.', 'anti-spam' ), [ 'status' => 400 ] );
		}

		$lockouts = (array) get_option( 'titan_bruteforce_lockouts', [] );
		$logged   = (array) get_option( 'titan_bruteforce_logged', [] );

		if ( ! isset( $lockouts[ $ip ] ) && ! isset( $logged[ $ip ] ) ) {
			return new \WP_Error( 'titan_client_not_found', __( 'No lockout record exists for this IP address.', 'anti-spam' ), [ 'status' => 404 ] );
		}

		$was_locked = isset( $lockouts[ $ip ] ) && $lockouts[ $ip ] > time();

		$response = self::dispatch( '/titan-security/v1/bruteforce/unlock', [ 'ip' => $ip ] );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		return [
			'ip'         => $ip,
			'was_locked' => $was_locked,
			'message'    => __( 'IP unlocked successfully.', 'anti-spam' ),
		];
	}

	/**
	 * Start a backup.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function start_backup() {
		if ( 'started' === get_option( 'titan_backup_status', 'stopped' ) ) {
			return new \WP_Error( 'titan_backup_in_progress', __( 'A backup is already running.', 'anti-spam' ), [ 'status' => 409 ] );
		}

		$response = Titan_Rest_Controller::get_instance()->start_backup();

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$status = (string) get_option( 'titan_backup_status', 'stopped' );

		if ( 'started' !== $status ) {
			return new \WP_Error( 'titan_backup_not_started', __( 'Failed to start backup.', 'anti-spam' ), [ 'status' => 500 ] );
		}

		return [
			'job_id'  => (string) get_option( 'titan_current_archive', '' ),
			'status'  => $status,
			'storage' => (string) get_option( 'titan_backup_store', 'local' ),
			'message' => __( 'Backup started.', 'anti-spam' ),
		];
	}

	/**
	 * List backups, including the progress of a running one.
	 *
	 * @param mixed $input Ability input.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function list_backups( $input = [] ) {
		$input      = self::normalize_input( $input );
		$controller = Titan_Rest_Controller::get_instance();
		$list       = $controller->get_backup_list();

		if ( is_wp_error( $list ) ) {
			return $list;
		}

		$progress = $controller->get_backup_progress();

		if ( is_wp_error( $progress ) ) {
			return $progress;
		}

		$list_data     = $list->get_data();
		$progress_data = $progress->get_data();
		$status        = is_array( $progress_data ) && isset( $progress_data['state'] ) ? (string) $progress_data['state'] : 'stopped';
		$running_id    = 'started' === $status ? (string) get_option( 'titan_current_archive', '' ) : '';
		$percent       = is_array( $progress_data ) && isset( $progress_data['progress'] ) ? (float) $progress_data['progress'] : 0.0;
		$job_id        = isset( $input['job_id'] ) ? sanitize_text_field( (string) $input['job_id'] ) : '';
		$backups       = [];

		if ( is_array( $list_data ) && isset( $list_data['backups'] ) && is_array( $list_data['backups'] ) ) {
			foreach ( $list_data['backups'] as $backup ) {
				$id = (string) $backup['date'];

				if ( '' !== $job_id && $job_id !== $id ) {
					continue;
				}

				$row = [
					'id'      => $id,
					'size'    => (string) $backup['size'],
					'storage' => (string) $backup['storage'],
					'status'  => 'completed',
				];

				if ( '' !== $running_id && $running_id === $id ) {
					$row['status']   = 'running';
					$row['progress'] = $percent;

					if ( is_array( $progress_data ) && ! empty( $progress_data['info']['size'] ) ) {
						$row['size'] = (string) $progress_data['info']['size'];
					}
				}

				$backups[] = $row;
			}
		}

		$paged = self::paginate( array_reverse( $backups ), $input );

		$output = [
			'backups'       => $paged['items'],
			'backup_status' => $status,
			'total'         => $paged['total'],
			'page'          => $paged['page'],
			'per_page'      => $paged['per_page'],
		];

		if ( '' === $job_id ) {
			return $output;
		}

		// An aborted backup is removed from the list, a finished one stays in it. The product records no failed state.
		if ( empty( $backups ) ) {
			$state   = 'cancelled';
			$current = 0;
			$message = __( 'Backup not found.', 'anti-spam' );
		} elseif ( $running_id === $job_id ) {
			$state   = 'working';
			$current = (int) floor( $percent );
			$message = __( 'Backup in progress...', 'anti-spam' );
		} else {
			$state   = 'completed';
			$current = 100;
			$message = __( 'Backup completed.', 'anti-spam' );
		}

		$output['job_id']   = $job_id;
		$output['state']    = $state;
		$output['progress'] = [
			'current' => $current,
			'total'   => 100,
			'message' => $message,
		];

		return $output;
	}
}
