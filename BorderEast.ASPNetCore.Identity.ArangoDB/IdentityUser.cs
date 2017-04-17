using BorderEast.ArangoDB.Client.Database;
using BorderEast.ArangoDB.Client.Database.Meta;
using BorderEast.ArangoDB.Client.Models;
using Microsoft.AspNetCore.Identity;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace BorderEast.ASPNetCore.Identity.ArangoDB
{
    public class IdentityUser : IdentityUser<IdentityRole> { }

    [Collection(HasForeignKey = true)]
    public class IdentityUser<TRole> : ArangoBaseEntity {

        public IdentityUser() {
            Roles = new List<TRole>();
            Logins = new List<UserLoginInfo>();
            Claims = new List<Claim>();
        }


        public string UserName { get; set; }


        public string Email { get; set; }


        public string NormalizedUserName { get; set; }


        public string NormalizedEmail { get; set; }


        public bool IsEmailConfirmed { get; set; }


        public string PhoneNumber { get; internal set; }


        public bool IsPhoneNumberConfirmed { get; internal set; }


        public string PasswordHash { get; set; }


        public string SecurityStamp { get; set; }


        public bool IsTwoFactorAuthEnabled { get; set; }


        public IList<UserLoginInfo> Logins { get; set; }

        [JsonConverter(typeof(ForeignKeyConverter))]
        public IList<TRole> Roles { get; set; }

        public IList<Claim> Claims { get; set; }


        public bool LockoutEnabled { get; set; }


        public DateTimeOffset? LockoutEndDate { get; set; }


        public int AccessFailedCount { get; set; }
    }
}
