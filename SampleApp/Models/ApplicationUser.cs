using BorderEast.ASPNetCore.Identity.ArangoDB;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SampleApp.Models
{
    // Add profile data for application users by adding properties to the ApplicationUser class
    [JsonObject(Id = "IdentityUser")]
    public class ApplicationUser : IdentityUser
    {
    }
}
