<?php
/**
 * This file is part of the Laminas\Permissions package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * PHP version 7
 *
 * @license GPL License
 */

declare(strict_types=1);

namespace Geo6\Laminas\Permissions;

use Geo6\Laminas\Log\Log;
use Laminas\Authentication\AuthenticationService;
use Laminas\Db\Adapter\Adapter as DbAdapter;
use Laminas\Db\Sql\Sql;
use Laminas\Db\Sql\TableIdentifier;
use Laminas\Log\Logger;
use Laminas\Permissions\Acl\Acl;
use Laminas\Permissions\Acl\Resource\GenericResource as Resource;
use Laminas\Permissions\Acl\Role\GenericRole as Role;

/**
 * Enable the use of Zend Framework ACL using PostgreSQL.
 *
 * @author Jonathan Beliën <jbe@geo6.be>
 *
 * @link https://docs.zendframework.com/zend-permissions-acl/
 */
class Permissions
{
    public $acl = null;
    private $_dbAdapter = null;
    private $_schema = null;
    private $_login = null;
    private $_logfile = null;

    /**
     * @param Laminas\Db\Adapter\Adapter $dbAdapter Database connection
     * @param string                     $schema    Database schema
     * @param string                     $logfile   Path to logfile
     */
    public function __construct(
        DbAdapter $dbAdapter,
        string $schema = null,
        string $logfile = null
    ) {
        $auth = new AuthenticationService();
        $this->_login = ($auth->hasIdentity() ? $auth->getIdentity() : 'anonymous');

        $this->_logfile = $logfile;

        $this->_dbAdapter = $dbAdapter;
        $this->_schema = $schema;

        $this->acl = new Acl();

        $sql = new Sql($this->_dbAdapter);

        // Roles
        $select = $sql->select(new TableIdentifier('role', $this->_schema));
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
        $select = $sql->select(new TableIdentifier('user', $this->_schema));
        $select->join(
            new TableIdentifier('user_role', $this->_schema),
            'user.id = user_role.id_user',
            []
        );
        $select->join(
            new TableIdentifier('role', $this->_schema),
            'user_role.id_role = role.id',
            ['name']
        );
        $select->columns([]);
        $select->where(['user.login' => $this->_login]);
        $select->order(['role.priority']);

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
        $select = $sql->select(new TableIdentifier('resource', $this->_schema));
        $select->columns(['name', 'public']);
        $select->order(['name']);

        $resources = $this->_dbAdapter->query(
            $sql->buildSqlString($select),
            DbAdapter::QUERY_MODE_EXECUTE
        );
        foreach ($resources as $resource) {
            $this->acl->addResource(new Resource($resource->name));

            if ($resource->public === true || $resource->public === 't') {
                $this->acl->allow($this->_login, $resource->name, 'connect');
            }
        }

        // Permissions
        $select = $sql->select(new TableIdentifier('role_resource', $this->_schema));
        $select->join(
            new TableIdentifier('role', $this->_schema),
            'role_resource.id_role = role.id',
            [
                'role_name' => 'name',
            ]
        );
        $select->join(
            new TableIdentifier('resource', $this->_schema),
            'role_resource.id_resource = resource.id',
            [
                'resource_name'   => 'name',
                'resource_locked' => 'locked',
            ]
        );
        $select->columns(['locked']);

        $permissions = $this->_dbAdapter->query(
            $sql->buildSqlString($select),
            DbAdapter::QUERY_MODE_EXECUTE
        );
        foreach ($permissions as $permission) {
            if (($permission->locked === false || $permission->locked === 'f')
                && ($permission->resource_locked === false || $permission->resource_locked === 'f')
            ) {
                $this->acl->allow(
                    $permission->role_name,
                    $permission->resource_name,
                    ($permission->role_name !== 'admin' ? 'connect' : null)
                );
            } else {
                $this->acl->deny(
                    $permission->role_name,
                    $permission->resource_name
                );
            }
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
    public function hasRole($r): bool
    {
        return $this->acl->hasRole($r);
    }

    /**
     * Returns true if and only if the Resource exists in the ACL.
     *
     * @param Laminas\Permissions\Acl\Resource\ResourceInterface|string $resource
     *
     * @return bool
     */
    public function hasResource($r): bool
    {
        return $this->acl->hasResource($r);
    }

    /**
     * Returns the identified Role.
     *
     * @param int|string $role
     */
    public function getRole($r)
    {
        $sql = new Sql($this->_dbAdapter);

        $select = $sql->select(new TableIdentifier('role', $this->_schema));
        if (is_int($r)) {
            $select->where(['id' => $r]);
        } else {
            $select->where(['name' => $r]);
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
     * @param int|string $role
     */
    public function getResource($r)
    {
        $sql = new Sql($this->_dbAdapter);

        $select = $sql->select(new TableIdentifier('resource', $this->_schema));
        if (is_int($r)) {
            $select->where(['id' => $r]);
        } else {
            $select->where(['name' => $r]);
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
    public function isRole($r): bool
    {
        return $this->acl->inheritsRole(new Role($this->_login), $r);
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
                if ($this->_login !== 'anonymous') {
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
     * @param Laminas\Permissions\Acl\Role\RoleInterface|string|array   $roles
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
     * @param Laminas\Permissions\Acl\Role\RoleInterface|string         $roles
     * @param Laminas\Permissions\Acl\Resource\ResourceInterface|string $resources
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
     * @param Laminas\Permissions\Acl\Role\RoleInterface|string         $roles
     * @param Laminas\Permissions\Acl\Resource\ResourceInterface|string $resources
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
