using BorderEast.ArangoDB.Client;
using BorderEast.ArangoDB.Client.Models;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace BorderEast.ASPNetCore.Identity.ArangoDB.Stores {
    public class UserStore {
    }

    public class UserStore<TUser> : UserStore<TUser, IdentityRole>
        where TUser : IdentityUser {

        public UserStore(IArangoClient arangoClient, IRoleStore<IdentityRole> roleStore)
            : base(arangoClient, roleStore) {
        }
    }

    public class UserStore<TUser, TRole> :
    StoreBase,
    IUserStore<TUser>,
    IUserClaimStore<TUser>,
    IUserLoginStore<TUser>,
    IUserRoleStore<TUser>,
    IUserPasswordStore<TUser>,
    IUserSecurityStampStore<TUser>,
    IUserTwoFactorStore<TUser>,
    IUserPhoneNumberStore<TUser>,
    IUserEmailStore<TUser>,
    IUserLockoutStore<TUser>
    where TUser : IdentityUser<TRole>
    where TRole : IdentityRole {

        private IRoleStore<TRole> roleStore;
        public UserStore(IArangoClient arangoClient, IRoleStore<TRole> roleStore)
            : base(arangoClient) {
            this.roleStore = roleStore;
            client = arangoClient;
        }

        public Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            if (claims == null) {
                throw new ArgumentNullException(nameof(claims));
            }

            foreach (Claim newClaim in claims) {
                user.Claims.Add(newClaim);
            }

            return Task.CompletedTask;
        }

        public Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            if (login == null) {
                throw new ArgumentNullException(nameof(login));
            }

            user.Logins.Add(
                //to avoid serializing properites from derived classes such as ExternalLoginInfo 
                //which in .net core 2.0 contains undetectable reference loop in Claims
                new UserLoginInfo(login.LoginProvider, login.ProviderKey, login.ProviderDisplayName));

            return Task.CompletedTask;
        }

        public async Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            if (roleName == null) {
                throw new ArgumentNullException(nameof(roleName));
            }

            // Check if the given role name exists
            TRole foundRole = await roleStore.FindByNameAsync(roleName, cancellationToken);

            if (foundRole == null) {
                throw new ArgumentException(nameof(roleName), $"The role with the given name {roleName} does not exist");
            }

            user.Roles.Add(foundRole);
        }

        public async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            // If no UserId was supplied, ArangoDb generates a key
            string key = null;
            try {
                var result = await client.DB().InsertAsync<TUser>(user);
                key = result.Key;
            } catch (Exception e) {
                var s = e;
            }
            user.Key = key;


            return string.IsNullOrEmpty(key) == false
                ? IdentityResult.Success
                : IdentityResult.Failed(new IdentityError() { Code = "Insert failed" });
            }

        public async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            try {
                await client.DB().DeleteAsync<TUser>(user.Id);
            }
            catch (Exception) {
                return IdentityResult.Failed();
            }

            return IdentityResult.Success;

        }

        public void Dispose() {
            // TODO: Workaround, gets disposed too early currently
            disposed = false;
        }

        public async Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (normalizedEmail == null) {
                throw new ArgumentNullException(nameof(normalizedEmail));
            }

            var result = await client.DB().GetByExampleAsync<TUser>(new { normalizedEmail = normalizedEmail });

            return result.FirstOrDefault();
        }

        public async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (userId == null) {
                throw new ArgumentNullException(nameof(userId));
            }

            if (userId.Contains("/")) {
                var ids = userId.Split('/');
                userId = ids[1];
            }

            TUser foundUser = await client.DB().GetByKeyAsync<TUser>(userId);

            return foundUser;
        }

        public async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (loginProvider == null) {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (loginProvider == null) {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            //for u in IdentityUser for l in u.logins filter l.loginProvider == @lp && l.providerKey == @pk return u
            var user = await client.DB().Query<TUser>("for u in IdentityUser " +
                      "let l = u.logins[*].loginProvider " +
                      "let p = u.logins[*].providerKey " +
                      "filter  @lp  in l and @pk in p " +
                      "return u")
                .WithParameters(new Dictionary<string, object> {  { "lp", loginProvider }, { "pk", providerKey} })
                .ToListAsync();

  

            return user.FirstOrDefault();
        }

        public async Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (normalizedUserName == null) {
                throw new ArgumentNullException(nameof(normalizedUserName));
            }


            var result = await client.DB().GetByExampleAsync<TUser>(new { normalizedUserName = normalizedUserName });

            if (result == null) {
                return (TUser)null;
            }

            return result.FirstOrDefault();
        }

        public Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.Claims);
        }

        public Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.IsEmailConfirmed);
        }

        public Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.LockoutEnabled);
        }

        public Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.LockoutEndDate);
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.Logins);
        }

        public Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.NormalizedEmail);
        }

        public Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.NormalizedUserName);
        }

        public Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.PasswordHash);
        }

        public Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.IsPhoneNumberConfirmed);
        }

        public Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            IList<string> userRoles = user.Roles.Select(r => r.Name).ToList();

            return Task.FromResult(userRoles);
        }

        public Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.SecurityStamp);
        }

        public Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.IsTwoFactorAuthEnabled);
        }

        public Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.Key);
        }

        public Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.UserName);
        }

        public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (claim == null) {
                throw new ArgumentNullException(nameof(claim));
            }

            var user = await client.DB().GetByExampleAsync<TUser>(new { claim = new { type = claim.Type, value = claim.Value } });


            return user;
        }

        public async Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (roleName == null) {
                throw new ArgumentNullException(nameof(roleName));
            }

            // TODO: refactor into AQL query


            var role = await client.DB().GetByExampleAsync<TRole>(new { name = roleName });

            if (role == null || role.Count == 0) {
                throw new KeyNotFoundException(nameof(roleName));
            }

            var users = await client.DB().Query<TUser>("FOR u in @@col FILTER @r in u.Roles RETURN u")
                .WithParameters(new Dictionary<string, object>() { { "@col", "IdentityUser" }, { "r", role.First().Key } })
                .ToListAsync();

            return users.ToList();
        }

        public Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.PasswordHash != null);
        }

        public Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            user.AccessFailedCount++;

            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            if (roleName == null) {
                throw new ArgumentNullException(nameof(roleName));
            }

            bool isInRole = user.Roles.Any(r => r.NormalizedName.Equals(roleName));

            return Task.FromResult(isInRole);
        }

        public Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            if (claims == null) {
                throw new ArgumentNullException(nameof(claims));
            }

            IEnumerable<Claim> foundClaims = user.Claims.Where(c => claims.Any(rc => rc.Equals(c)));

            foreach (Claim claimToRemove in foundClaims) {
                user.Claims.Remove(claimToRemove);
            }

            return Task.CompletedTask;
        }

        public Task RemoveFromRoleAsync(TUser user, string roleName, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            if (roleName == null) {
                throw new ArgumentNullException(nameof(roleName));
            }

            TRole roleToRemove = user.Roles.FirstOrDefault(r => r.NormalizedName == roleName);

            if (roleToRemove != null) {
                user.Roles.Remove(roleToRemove);
            }

            return Task.CompletedTask;
        }

        public Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            if (loginProvider == null) {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (providerKey == null) {
                throw new ArgumentNullException(nameof(providerKey));
            }

            UserLoginInfo userLoginToRemove = user.Logins.FirstOrDefault(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey);

            if (userLoginToRemove != null) {
                user.Logins.Remove(userLoginToRemove);
            }

            return Task.CompletedTask;
        }

        public Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            if (claim == null) {
                throw new ArgumentNullException(nameof(claim));
            }

            if (newClaim == null) {
                throw new ArgumentNullException(nameof(newClaim));
            }

            if (user.Claims.Any(c => c.Equals(claim))) {
                user.Claims.Remove(claim);
                user.Claims.Add(newClaim);
            }

            return Task.CompletedTask;
        }

        public Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            user.AccessFailedCount = 0;

            return Task.CompletedTask;
        }

        public Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            user.Email = email;

            return Task.FromResult(user.Email);
        }

        public Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            user.IsEmailConfirmed = confirmed;

            return Task.FromResult(user.Email);
        }

        public Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            user.LockoutEnabled = enabled;

            return Task.CompletedTask;
        }

        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            user.LockoutEndDate = lockoutEnd;

            return Task.CompletedTask;
        }

        public Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            user.NormalizedEmail = normalizedEmail;

            return Task.FromResult(user.Email);
        }

        public Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            user.NormalizedUserName = normalizedName ?? throw new ArgumentNullException(nameof(normalizedName));

            return Task.CompletedTask;
        }

        public Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            user.PasswordHash = passwordHash ?? throw new ArgumentNullException(nameof(passwordHash));

            return Task.CompletedTask;
        }

        public Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            user.PhoneNumber = phoneNumber;

            return Task.CompletedTask;
        }

        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            user.IsPhoneNumberConfirmed = confirmed;

            return Task.CompletedTask;
        }

        public Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            user.SecurityStamp = stamp;

            return Task.CompletedTask;
        }

        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            user.IsTwoFactorAuthEnabled = enabled;

            return Task.CompletedTask;
        }

        public Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            user.UserName = userName ?? throw new ArgumentNullException(nameof(userName));

            return Task.CompletedTask;
        }

        public async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            try {

                var result = await client.DB().UpdateAsync(user.Key, user);

                user = result.New;

            }
            catch (Exception) {
                return IdentityResult.Failed();
            }

            return IdentityResult.Success;
        }

    }

}
