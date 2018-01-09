<?php

namespace Geo6\Zend\Permissions;

use Log;
use Zend\Authentication\AuthenticationService;
use Zend\Db\Adapter\Adapter as DbAdapter;
use Zend\Log\Logger;
use Zend\Permissions\Acl\Acl;
use Zend\Permissions\Acl\Resource\GenericResource as Resource;
use Zend\Permissions\Acl\Role\GenericRole as Role;

class Permissions
{
    private $dbAdapter = null;
    public $acl = null;
    private $login = null;

    public function __construct()
    {
        $auth = new AuthenticationService();
        $this->login = (!is_null($auth->getIdentity()) ? $auth->getIdentity() : 'anonymous');

        $this->dbAdapter = new DbAdapter([
      'driver'   => 'Pgsql',
      'hostname' => SQL_SERVER,
      'database' => strtolower(substr(SQL_LOGIN, strpos(SQL_LOGIN, '_') + 1)),
      'username' => strtolower(SQL_LOGIN),
      'password' => SQL_PASSWORD,
    ]);
        $this->dbAdapter->query(
      'SET search_path TO access;',
      DbAdapter::QUERY_MODE_EXECUTE
    );

        $this->acl = new Acl();

        $q = $this->dbAdapter->query('SELECT "name" FROM "role" ORDER BY "name"', DbAdapter::QUERY_MODE_EXECUTE);
        while ($r = $q->current()) {
            $this->acl->addRole(new Role($r->name));
            $q->next();
            if ($q->valid() !== true) {
                break;
            }
        }

        $parents = [];
        $q = $this->dbAdapter->query('SELECT r."name" FROM "user" u JOIN "user_role" ur ON u."id" = ur."id_user" JOIN "role" r ON ur."id_role" = r."id" WHERE u."login" = $1 ORDER BY r."priority" ASC', [$this->login]);
        while ($r = $q->current()) {
            $parents[] = $r->name;
            $q->next();
            if ($q->valid() !== true) {
                break;
            }
        }
        $this->acl->addRole(new Role($this->login), $parents);

        $q = $this->dbAdapter->query('SELECT "name", "public" FROM "resource" ORDER BY "name"', DbAdapter::QUERY_MODE_EXECUTE);
        while ($r = $q->current()) {
            $this->acl->addResource(new Resource($r->name));
            if ($r->public === 't') {
                $this->acl->allow($this->login, $r->name, 'connect');
            }

            $q->next();
            if ($q->valid() !== true) {
                break;
            }
        }

        $q = $this->dbAdapter->query('SELECT rr."locked", ro."name" AS "role_name", re."name" AS "resource_name", re."locked" AS "resource_locked" FROM "role_resource" rr JOIN "role" ro ON rr."id_role" = ro."id" JOIN "resource" re ON rr."id_resource" = re."id"', DbAdapter::QUERY_MODE_EXECUTE);
        while ($r = $q->current()) {
            if ($r->locked !== 't' && $r->resource_locked !== 't') {
                $this->acl->allow($r->role_name, $r->resource_name, ($r->role_name !== 'admin' ? 'connect' : null));
            } else {
                $this->acl->deny($r->role_name, $r->resource_name);
            }

            $q->next();
            if ($q->valid() !== true) {
                break;
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
        if (is_int($r)) {
            $q = $this->dbAdapter->query('SELECT * FROM "role" WHERE "id" = $1', [$r]);
        } else {
            $q = $this->dbAdapter->query('SELECT * FROM "role" WHERE "name" = $1', [$r]);
        }

        return $q->current();
    }

    public function getResource($r)
    {
        if (is_int($r)) {
            $q = $this->dbAdapter->query('SELECT * FROM "resource" WHERE "id" = $1', [$r]);
        } else {
            $q = $this->dbAdapter->query('SELECT * FROM "resource" WHERE "name" = $1', [$r]);
        }

        return $q->current();
    }

    public function isRole($r)
    {
        return $this->acl->inheritsRole(new Role($this->login), $r);
    }

    public function isAllowed($resource, $privilege = null, $relog = false)
    {
        if (is_bool($privilege)) {
            $relog = $privilege;
            $privilege = 'connect';
        }

        if (!in_array(substr($resource, 0, strpos($resource, '-')), ['home', 'tools', 'app'])) {
            $resource = 'app-'.$resource;
        }

        try {
            if (!is_null($privilege)) {
                $is_allowed = $this->acl->isAllowed($this->login, $resource, $privilege);
            } else {
                $is_allowed = $this->acl->isAllowed($this->login, $resource, 'connect');
            }

            if ($is_allowed !== true && $relog === true) {
                $auth = new AuthenticationService();

                if ($auth->hasIdentity()) {
                    Log::write(LOGPATH.'/login.log', 'Access to resource "{resource}" is denied for user "{login}".', ['resource' => $resource, 'login' => $auth->getIdentity()], Logger::WARN);
                } else {
                    Log::write(LOGPATH.'/login.log', 'Access to resource "{resource}" is denied : no user logged in.', ['resource' => $resource], Logger::WARN);
                }

                $dbAdapter = new DbAdapter([
          'driver'   => 'Pgsql',
          'hostname' => SQL_SERVER,
          'database' => strtolower(substr(SQL_LOGIN, strpos(SQL_LOGIN, '_') + 1)),
          'username' => strtolower(SQL_LOGIN),
          'password' => SQL_PASSWORD,
        ]);
                $dbAdapter->query(
          'SET search_path TO access;',
          DbAdapter::QUERY_MODE_EXECUTE
        );
                $q = $dbAdapter->query('SELECT "url" FROM "resource" WHERE "name" = $1 LIMIT 1', [$resource]);
                $r = $q->current();

                header('Location: /index.php?redirect_to='.urlencode($r->url).($auth->hasIdentity() ? '' : '&nologin'));
                exit();
            }

            return $is_allowed;
        } catch (Exception $e) {
            Log::write(LOGPATH.'/login.log', $e->getMessage(), [], Logger::ERR);
            if ($relog === true) {
                header('Location: /index.php');
                exit();
            }

            return false;
        }
    }

    public function isGranted($resource, $relog = false)
    {
        return $this->isAllowed($resource, $relog);
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
