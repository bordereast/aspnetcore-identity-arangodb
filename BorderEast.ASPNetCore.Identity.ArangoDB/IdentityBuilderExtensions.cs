using BorderEast.ASPNetCore.Identity.ArangoDB.Stores;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Text;

namespace BorderEast.ASPNetCore.Identity.ArangoDB
{
    public static class IdentityBuilderExtensions {

        public static IdentityBuilder AddArangoDbStores(this IdentityBuilder builder) {

            builder.Services.AddSingleton(
                typeof(IRoleStore<>).MakeGenericType(builder.RoleType),
                typeof(RoleStore<>).MakeGenericType(builder.RoleType));

            builder.Services.AddSingleton(
                typeof(IUserStore<>).MakeGenericType(builder.UserType),
                typeof(UserStore<,>).MakeGenericType(builder.UserType, builder.RoleType));

            builder.Services.AddTransient<ILookupNormalizer, LookupNormalizer>();

            return builder;
        }
    }
}
