[![Latest Stable Version](https://poser.pugx.org/geo6/zend-acl-postgresql/v/stable)](https://packagist.org/packages/geo6/zend-acl-postgresql)
[![Total Downloads](https://poser.pugx.org/geo6/zend-acl-postgresql/downloads)](https://packagist.org/packages/geo6/zend-acl-postgresql)
[![Monthly Downloads](https://poser.pugx.org/geo6/zend-acl-postgresql/d/monthly.png)](https://packagist.org/packages/geo6/zend-acl-postgresql)

# [Zend Permissions ACL](https://docs.zendframework.com/zend-permissions-acl/) with [PostgreSQL](https://www.postgresql.org/)

## Install

    composer require geo6/zend-acl-postgresql

### Database structure

See [INSTALL.md](./INSTALL.md)

> For the purposes of this documentation:
>
>    a **resource** is an object to which access is controlled.
>    a **role** is an object that may request access to a **resource**.
>
> Put simply, **roles request access to resources**. For example, if a parking attendant requests access to a car, then the parking attendant is the requesting role, and the car is the resource, since access to the car may not be granted to everyone.
>
> --- <https://docs.zendframework.com/zend-permissions-acl/usage/>

#### Table `resource`

| Column name | Column description |
|-------------|--------------------|
| id | `int` Identifier (AUTONUM) |
| name | Name of the resource |
| url | URL of the resource |
| locked | `bool` Allows to deny access to the resource for everyone |
| public | `bool` Allows to set the resource accessible to everyone - even without login |

#### Table `role`

| Column name | Column description |
|-------------|--------------------|
| id | `int` Identifier (AUTONUM) |
| name | Name of the role |
| priority | `int` Priority of the resource - Rules will be applied following the priority |

#### Table `user`

| Column name | Column description |
|-------------|--------------------|
| id | `int` Identifier (AUTONUM) |
| login | Login of the user (= username) |
| password | Encrypted password of the user |
| email | Email address of the user |
| fullname | Full name of the user |
| home | `int` Identifier resource used to be the homepage of the user. The user will be automatically redirected to his/her homepage once logged in. |
| locked | `bool` Allows to deny access to everything for this user. The user won't be able to log in. |

#### Table `role_resource`

Grant access for a role to a resource.

#### Table `user_role`

Assign a user to a role.
