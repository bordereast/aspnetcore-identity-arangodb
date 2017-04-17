using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Text;

namespace BorderEast.ASPNetCore.Identity.ArangoDB
{
    public class LookupNormalizer : ILookupNormalizer {

        /// <summary>
        /// Convert string to lower case invariant
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public string Normalize(string key) {
            return key.Normalize().ToLowerInvariant();
        }

    }
}
