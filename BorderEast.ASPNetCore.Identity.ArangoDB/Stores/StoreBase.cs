using BorderEast.ArangoDB.Client;
using System;
using System.Collections.Generic;
using System.Text;

namespace BorderEast.ASPNetCore.Identity.ArangoDB.Stores
{
    public class StoreBase {
        protected bool disposed = false;

        protected IArangoClient client;

        protected StoreBase(IArangoClient arangoClient) {
            this.client = arangoClient;
        }

        protected virtual void ThrowIfDisposed() {
            if (disposed) {
                throw new ObjectDisposedException(GetType().Name);
            }
        }


    }
}
