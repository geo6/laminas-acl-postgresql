<?php

declare(strict_types=1);

namespace Geo6\Laminas\Permissions;

use Exception;
use Geo6\Laminas\Log\Log;
use Laminas\Authentication\AuthenticationService;
use Laminas\Db\Adapter\Adapter as DbAdapter;
use Laminas\Db\Sql\Sql;
use Laminas\Db\Sql\TableIdentifier;
use Laminas\Log\Logger;
use Laminas\Permissions\Acl\Acl;
use Laminas\Permissions\Acl\Resource\GenericResource as Resource;
use Laminas\Permissions\Acl\Role\GenericRole as Role;
use Mezzio\Authentication\DefaultUser;
use Mezzio\Authentication\UserInterface;

/**
 * Enable the use of Zend Framework ACL using PostgreSQL.
 *
 * @link https://docs.laminas.dev/laminas-permissions-acl/
 */
class Permissions
{
    public $acl = null;

    private $_dbAdapter = null;
    private $_logfile = null;
    private $_login = null;
    private $_schema = null;
    private $_tables = null;
    private $_user = null;

    /**
     * @param Laminas\Db\Adapter\Adapter $dbAdapter Database connection
     * @param string                     $schema    Database schema
     * @param array                      $tables    Database ACL tables
     * @param string                     $logfile   Path to logfile
     */
    public function __construct(
        DbAdapter $dbAdapter,
        ?string $schema = null,
        ?array $tables = null,
        ?string $logfile = null
    ) {
        $auth = new AuthenticationService();
        if ($auth->hasIdentity() === true) {
            $this->_login = $auth->getIdentity();
        } elseif (isset($_SESSION[UserInterface::class])) {
            $user = $_SESSION[UserInterface::class];

            $this->_user = new DefaultUser($user['username'], $user['roles'] ?? [], $user['details'] ?? []);
            $this->_login = $this->_user->getIdentity();
        }

        $this->_logfile = $logfile;

        $this->_dbAdapter = $dbAdapter;
        $this->_schema = is_null($schema) ? 'public' : $schema;
        $this->_tables = is_null($tables) ? [] : $tables;

        $this->acl = new Acl();

        $sql = new Sql($this->_dbAdapter);

        // Roles
        $select = $sql->select(new TableIdentifier($this->_tables['role'] ?? 'role', $this->_schema));
        $select->columns(['name']);
        $select->order(['name']);

        $roles = $this->_dbAdapter->query(
            $sql->buildSqlString($select),
            DbAdapter::QUERY_MODE_EXECUTE
        );
        foreach ($roles as $role) {
            $this->acl->addRole(new Role($role->name));
        }

        // Apply roles to user
        $select = $sql->select(['u' => new TableIdentifier($this->_tables['user'] ?? 'user', $this->_schema)]);
        $select->join(
            ['ur' => new TableIdentifier($this->_tables['user_role'] ?? 'user_role', $this->_schema)],
            'u.id = ur.id_user',
            []
        );
        $select->join(
            ['r' => new TableIdentifier($this->_tables['role'] ?? 'role', $this->_schema)],
            'ur.id_role = r.id',
            ['name']
        );
        $select->columns([]);
        $select->where(['u.login' => $this->_login]);
        $select->order(['r.priority']);

        $parents = [];
        $roles = $this->_dbAdapter->query(
            $sql->buildSqlString($select),
            DbAdapter::QUERY_MODE_EXECUTE
        );
        foreach ($roles as $role) {
            $parents[] = $role->name;
        }
        $this->acl->addRole(new Role($this->_login), $parents);

        // Resources
        $select = $sql->select(new TableIdentifier($this->_tables['resource'] ?? 'resource', $this->_schema));
        $select->columns(['name'/*, 'public'*/]);
        $select->order(['name']);

        $resources = $this->_dbAdapter->query(
            $sql->buildSqlString($select),
            DbAdapter::QUERY_MODE_EXECUTE
        );
        foreach ($resources as $resource) {
            $this->acl->addResource(new Resource($resource->name));

            // if ($resource->public === true || $resource->public === 't') {
            //     $this->acl->allow($this->_login, $resource->name, 'connect');
            // }
        }

        // Permissions
        $select = $sql->select(['rr' => new TableIdentifier($this->_tables['role_resource'] ?? 'role_resource', $this->_schema)]);
        $select->join(
            ['ro' => new TableIdentifier($this->_tables['role'] ?? 'role', $this->_schema)],
            'rr.id_role = ro.id',
            [
                'role_name' => 'name',
            ]
        );
        $select->join(
            ['re' => new TableIdentifier($this->_tables['resource'] ?? 'resource', $this->_schema)],
            'rr.id_resource = re.id',
            [
                'resource_name'   => 'name',
                // 'resource_locked' => 'locked',
            ]
        );
        // $select->columns(['locked']);

        $permissions = $this->_dbAdapter->query(
            $sql->buildSqlString($select),
            DbAdapter::QUERY_MODE_EXECUTE
        );
        foreach ($permissions as $permission) {
            // if (($permission->locked === false || $permission->locked === 'f')
            //     && ($permission->resource_locked === false || $permission->resource_locked === 'f')
            // ) {
            $this->acl->allow(
                $permission->role_name,
                $permission->resource_name,
                'connect'
            );
            // } else {
            //     $this->acl->deny(
            //         $permission->role_name,
            //         $permission->resource_name
            //     );
            // }
        }
    }

    /**
     * @return array of registered roles
     */
    public function getRoles(): array
    {
        return $this->acl->getRoles();
    }

    /**
     * @return array of registered resources
     */
    public function getResources(): array
    {
        return $this->acl->getResources();
    }

    /**
     * Returns true if and only if the Role exists in the registry.
     *
     * @param Laminas\Permissions\Acl\Role\RoleInterface|string $role
     *
     * @return bool
     */
    public function hasRole($role): bool
    {
        return $this->acl->hasRole($role);
    }

    /**
     * Returns true if and only if the Resource exists in the ACL.
     *
     * @param Laminas\Permissions\Acl\Resource\ResourceInterface|string $resource
     *
     * @return bool
     */
    public function hasResource($resource): bool
    {
        return $this->acl->hasResource($resource);
    }

    /**
     * Returns the identified Role.
     *
     * @param int|string $role
     */
    public function getRole($role)
    {
        $sql = new Sql($this->_dbAdapter);

        $select = $sql->select(new TableIdentifier($this->_tables['role'] ?? 'role', $this->_schema));
        if (is_int($role)) {
            $select->where(['id' => $role]);
        } else {
            $select->where(['name' => $role]);
        }

        $q = $this->_dbAdapter->query(
            $sql->buildSqlString($select),
            DbAdapter::QUERY_MODE_EXECUTE
        );

        return $q->current();
    }

    /**
     * Returns the identified Resource.
     *
     * @param int|string $resource
     */
    public function getResource($resource)
    {
        $sql = new Sql($this->_dbAdapter);

        $select = $sql->select(new TableIdentifier($this->_tables['resource'] ?? 'resource', $this->_schema));
        if (is_int($resource)) {
            $select->where(['id' => $resource]);
        } else {
            $select->where(['name' => $resource]);
        }

        $q = $this->_dbAdapter->query(
            $sql->buildSqlString($select),
            DbAdapter::QUERY_MODE_EXECUTE
        );

        return $q->current();
    }

    /**
     * Returns true if and only if current user inherits from $role.
     *
     * @param Laminas\Permissions\Acl\Role\RoleInterface|string $role
     *
     * @return bool
     */
    public function isRole($role): bool
    {
        return $this->acl->inheritsRole(new Role($this->_login), $role);
    }

    /**
     * Returns true if and only if the current user has access to the Resource.
     *
     * @param Laminas\Permissions\Acl\Resource\ResourceInterface|string $resource
     * @param string                                                    $privilege
     * @param bool                                                      $log       Enable logging
     *
     * @return bool
     */
    public function isAllowed($resource, $privilege = null, $log = true): bool
    {
        try {
            $is_allowed = $this->acl->isAllowed(
                $this->_login,
                $resource,
                $privilege ?? 'connect'
            );

            if ($is_allowed !== true && $log === true && !is_null($this->_logfile)) {
                if (!is_null($this->_login)) {
                    Log::write(
                        $this->_logfile,
                        'Access to resource "{resource}" ({privilege}) is denied for user "{login}".',
                        [
                            'resource'  => $resource,
                            'privilege' => $privilege,
                            'login'     => $this->_login,
                        ],
                        Logger::WARN
                    );
                } else {
                    Log::write(
                        $this->_logfile,
                        'Access to resource "{resource}" ({privilege}) is denied : no user logged in.',
                        [
                            'resource'  => $resource,
                            'privilege' => $privilege,
                        ],
                        Logger::WARN
                    );
                }
            }

            return $is_allowed;
        } catch (Exception $e) {
            if (!is_null($this->_logfile)) {
                Log::write($this->_logfile, $e->getMessage(), [], Logger::ERR);
            }

            return false;
        }
    }

    /**
     * @see Pemission::isAllowed()
     */
    public function isGranted($resource, $privilege = null, $log = true): bool
    {
        return $this->isAllowed($resource, $privilege);
    }

    /**
     * Adds an "allow" rule to the ACL.
     *
     * @param Laminas\Permissions\Acl\Role\RoleInterface|string|array   $role
     * @param Laminas\Permissions\Acl\Resource\ResourceInterface|string $resource
     * @param string|array                                              $privileges
     *
     * @return Laminas\Permissions\Acl
     */
    public function allowPrivilege($role, $resource, $privileges)
    {
        if (is_null($role)) {
            $role = $this->_login;
        }

        return $this->acl->allow($role, $resource, $privileges);
    }

    /**
     * Removes "allow" permissions from the ACL.
     *
     * @param Laminas\Permissions\Acl\Role\RoleInterface|string         $role
     * @param Laminas\Permissions\Acl\Resource\ResourceInterface|string $resource
     * @param string|array                                              $privileges
     *
     * @return Laminas\Permissions\Acl
     */
    public function removeAllowPrivilege($role, $resource, $privileges)
    {
        if (is_null($role)) {
            $role = $this->_login;
        }

        return $this->acl->removeAllow($role, $resource, $privileges);
    }

    /**
     * Adds a "deny" rule to the ACL.
     *
     * @param Laminas\Permissions\Acl\Role\RoleInterface|string         $role
     * @param Laminas\Permissions\Acl\Resource\ResourceInterface|string $resource
     * @param string|array                                              $privileges
     *
     * @return Laminas\Permissions\Acl
     */
    public function denyPrivilege($role, $resource, $privileges)
    {
        if (is_null($role)) {
            $role = $this->_login;
        }

        return $this->acl->deny($role, $resource, $privileges);
    }

    /**
     * Removes "deny" restrictions from the ACL.
     *
     * @param Laminas\Permissions\Acl\Role\RoleInterface|string         $role
     * @param Laminas\Permissions\Acl\Resource\ResourceInterface|string $resource
     * @param string|array                                              $privileges
     *
     * @return Laminas\Permissions\Acl
     */
    public function removeDenyPrivilege($role, $resource, $privileges)
    {
        if (is_null($role)) {
            $role = $this->_login;
        }

        return $this->acl->removeDeny($role, $resource, $privileges);
    }
}
