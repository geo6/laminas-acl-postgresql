<?php

namespace Geo6\Zend\Permissions;

use Geo6\Zend\Log\Log;
use Zend\Authentication\AuthenticationService;
use Zend\Db\Adapter\Adapter as DbAdapter;
use Zend\Db\Sql\Sql;
use Zend\Db\Sql\TableIdentifier;
use Zend\Log\Logger;
use Zend\Permissions\Acl\Acl;
use Zend\Permissions\Acl\Resource\GenericResource as Resource;
use Zend\Permissions\Acl\Role\GenericRole as Role;

class Permissions
{
    public $acl = null;
    private $dbAdapter = null;
    private $schema = null;
    private $login = null;
    private $logfile = null;

    public function __construct(DbAdapter $dbAdapter, string $schema = null, string $logfile = null)
    {
        $auth = new AuthenticationService();
        $this->login = ($auth->hasIdentity() ? $auth->getIdentity() : 'anonymous');

        $this->logfile = $logfile;

        $this->dbAdapter = $dbAdapter;
        $this->schema = $schema;

        $this->acl = new Acl();

        $sql = new Sql($this->dbAdapter);

        // Roles
        $select = $sql->select(new TableIdentifier('role', $this->schema));
        $select->columns(['name']);
        $select->order(['name']);

        $roles = $this->dbAdapter->query($sql->buildSqlString($select), DbAdapter::QUERY_MODE_EXECUTE);
        foreach ($roles as $role) {
            $this->acl->addRole(new Role($role->name));
        }

        // Apply roles to user
        $select = $sql->select(new TableIdentifier('user', $this->schema));
        $select->join(new TableIdentifier('user_role', $this->schema), 'user.id = user_role.id_user', []);
        $select->join(new TableIdentifier('role', $this->schema), 'user_role.id_role = role.id', ['name']);
        $select->columns([]);
        $select->where(['user.login' => $this->login]);
        $select->order(['role.priority']);

        $parents = [];
        $roles = $this->dbAdapter->query($sql->buildSqlString($select), DbAdapter::QUERY_MODE_EXECUTE);
        foreach ($roles as $role) {
            $parents[] = $role->name;
        }
        $this->acl->addRole(new Role($this->login), $parents);

        // Resources
        $select = $sql->select(new TableIdentifier('resource', $this->schema));
        $select->columns(['name', 'public']);
        $select->order(['name']);

        $resources = $this->dbAdapter->query($sql->buildSqlString($select), DbAdapter::QUERY_MODE_EXECUTE);
        foreach ($resources as $resource) {
            $this->acl->addResource(new Resource($resource->name));

            if ($resource->public === true) {
                $this->acl->allow($this->login, $resource->name, 'connect');
            }
        }

        // Permissions
        $select = $sql->select(new TableIdentifier('role_resource', $this->schema));
        $select->join(
            new TableIdentifier('role', $this->schema),
            'role_resource.id_role = role.id',
            [
                'role_name' => 'name',
            ]
        );
        $select->join(
            new TableIdentifier('resource', $this->schema),
            'role_resource.id_resource = resource.id',
            [
                'resource_name'   => 'name',
                'resource_locked' => 'locked',
            ]
        );
        $select->columns(['locked']);

        $permissions = $this->dbAdapter->query($sql->buildSqlString($select), DbAdapter::QUERY_MODE_EXECUTE);
        foreach ($permissions as $permission) {
            if (($permission->locked === false || $permission->locked === 'f') && ($permission->resource_locked === false || $permission->resource_locked === 'f')) {
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

    public function getRoles()
    {
        return $this->acl->getRoles();
    }

    public function getResources()
    {
        return $this->acl->getResources();
    }

    public function hasRole($r)
    {
        return $this->acl->hasRole($r);
    }

    public function hasResource($r)
    {
        return $this->acl->hasResource($r);
    }

    public function getRole($r)
    {
        $sql = new Sql($this->dbAdapter);

        $select = $sql->select(new TableIdentifier('role', $this->schema));
        if (is_int($r)) {
            $select->where(['id' => $r]);
        } else {
            $select->where(['name' => $r]);
        }

        $q = $this->dbAdapter->query($sql->buildSqlString($select), DbAdapter::QUERY_MODE_EXECUTE);

        return $q->current();
    }

    public function getResource($r)
    {
        $sql = new Sql($this->dbAdapter);

        $select = $sql->select(new TableIdentifier('resource', $this->schema));
        if (is_int($r)) {
            $select->where(['id' => $r]);
        } else {
            $select->where(['name' => $r]);
        }

        $q = $this->dbAdapter->query($sql->buildSqlString($select), DbAdapter::QUERY_MODE_EXECUTE);

        return $q->current();
    }

    public function isRole($r)
    {
        return $this->acl->inheritsRole(new Role($this->login), $r);
    }

    public function isAllowed($resource, $privilege = null)
    {
        try {
            $is_allowed = $this->acl->isAllowed($this->login, $resource, $privilege ?? 'connect');

            if ($is_allowed !== true && !is_null($this->logfile)) {
                if ($this->login !== 'anonymous') {
                    Log::write(
                        $this->logfile,
                        'Access to resource "{resource}" ({privilege}) is denied for user "{login}".',
                        [
                            'resource'  => $resource,
                            'privilege' => $privilege,
                            'login'     => $this->login,
                        ],
                        Logger::WARN
                    );
                } else {
                    Log::write(
                        $this->logfile,
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
            if (!is_null($this->logfile)) {
                Log::write($this->logfile, $e->getMessage(), [], Logger::ERR);
            }

            return false;
        }
    }

    public function isGranted($resource)
    {
        return $this->isAllowed($resource);
    }

    public function allowPrivilege($role, $resource, $privileges)
    {
        if (is_null($role)) {
            $role = $this->login;
        }

        return $this->acl->allow($role, $resource, $privileges);
    }

    public function removeAllowPrivilege($role, $resource, $privileges)
    {
        if (is_null($role)) {
            $role = $this->login;
        }

        return $this->acl->removeAllow($role, $resource, $privileges);
    }

    public function denyPrivilege($role, $resource, $privileges)
    {
        if (is_null($role)) {
            $role = $this->login;
        }

        return $this->acl->deny($role, $resource, $privileges);
    }

    public function removeDenyPrivilege($role, $resource, $privileges)
    {
        if (is_null($role)) {
            $role = $this->login;
        }

        return $this->acl->removeDeny($role, $resource, $privileges);
    }
}
