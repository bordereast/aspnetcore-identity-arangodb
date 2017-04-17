using BorderEast.ArangoDB.Client.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace BorderEast.ASPNetCore.Identity.ArangoDB
{
    [JsonObject(Id = "IdentityRole")]
    public class IdentityRole : ArangoBaseEntity {
        public IdentityRole() {
            Claims = new List<Claim>();
        }

        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Include)]
        public string Name { get; set; }

        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Include)]
        public string NormalizedName { get; set; }

        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Include)]
        public IList<Claim> Claims { get; set; }
    }
}
