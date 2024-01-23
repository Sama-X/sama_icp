# Sama Network

All data incurred from our daily internet usage are being hijacked, monitored and analyzed by centralized companies.Traditional blockchain systems often construct on-chain assets and contract data for privacy, yet lack of effective privacy and security protection for specific business data. Meanwhile, the emergence of AI and the explosive growth of computation power demand by small and medium AI models in research and commercialization, the trend of anti-globalization has also brought about the division of computational power. That’s when  platforms like BOINC shines as it shares the dividends brought about by the development of the rising distributed computing market. SAMA network, with its original designed consensus and business sharding separation, builds a highly secure and private distributed computational system. It provides data security and computational power for the World Wide Web without altering users’ habits.

Features 
- Provides high throughput business sharding node service specific to distributed businesses
- Full stack encryption for thorough business related data
- Provides high-quality distributed computation service

# function 
The reference system data of all nodes in SAMA network is dynamically uploaded to the ICP, where the dynamic reference system data includes the node’s IP address, node bandwidth, node reputation score, connectivity between nodes and neighbor nodes, etc. Reference system data, at a certain frequency ( For example, SAMA is uploaded once every 10 minutes on the whole network) to upload ICP. The application on sama needs to pull these reference system data through ICP. The application relies on these reference system data to optimize the scheduling strategy of its own application, and then delivers the data to SAMA through the interface. Network, so that the application can get a better experience.
  SAMA network provides routing, encryption and computing services to web2 and web3 applications. Applications can upload useful data to ICP independently, and SAMA will provide an interface compatible with data upload to ICP. For example, ChatTEN, a sama use case, currently has 2000+ users. It is a distributed chatGPT client, No sign-up required, Break through area limitations, Full - stack encryption of data, Plug - and - play. Users can select useful conversation and chat data to upload to ICP for users to archive.

# Provide metadata
1. Webset URL https://sama.network/ 
2. Canister URL of your project  https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=k2xwn-cqaaa-aaaan-qd4gq-cai
3. Discord URL https://discord.gg/D5mBu4kJp7
4. Twitter URL https://twitter.com/sama_network
5. Youtube URL https://www.youtube.com/@sama_network


# implementation
## rust_profile ##
Welcome to your new rust_profile project and to the internet computer development community. By default, creating a new project adds this README and some template files to your project directory. You can edit these template files to customize your project and to include your own code to speed up the development cycle.

To get started, you might want to explore the project directory structure and the default configuration file. Working with this project in your development environment will not affect any production deployment or identity tokens.

To learn more before you start working with rust_profile, see the following documentation available online:

- [Quick Start](https://internetcomputer.org/docs/quickstart/quickstart-intro)
- [SDK Developer Tools](https://internetcomputer.org/docs/developers-guide/sdk-guide)
- [Rust Canister Devlopment Guide](https://internetcomputer.org/docs/rust-guide/rust-intro)
- [ic-cdk](https://docs.rs/ic-cdk)
- [ic-cdk-macros](https://docs.rs/ic-cdk-macros)
- [Candid Introduction](https://internetcomputer.org/docs/candid-guide/candid-intro)
- [JavaScript API Reference](https://erxue-5aaaa-aaaab-qaagq-cai.raw.icp0.io)

If you want to start working on your project right away, you might want to try the following commands:

```bash
cd rust_profile/
dfx help
dfx canister --help
```

-- Running the project locally --

If you want to test your project locally, you can use the following commands:

```bash
# Starts the replica, running in the background
dfx start --background

# Deploys your canisters to the replica and generates your candid interface
dfx deploy
```

Once the job completes, your application will be available at `http://localhost:4943?canisterId={asset_canister_id}`.

If you have made changes to your backend canister, you can generate a new candid interface with

```bash
npm run generate
```

at any time. This is recommended before starting the frontend development server, and will be run automatically any time you run `dfx deploy`.

If you are making frontend changes, you can start a development server with

```bash
npm start
```

Which will start a server at `http://localhost:8080`, proxying API requests to the replica at port 4943.


### Note on frontend environment variables ###

If you are hosting frontend code somewhere without using DFX, you may need to make one of the following adjustments to ensure your project does not fetch the root key in production:

- set`DFX_NETWORK` to `production` if you are using Webpack
- use your own preferred method to replace `process.env.DFX_NETWORK` in the autogenerated declarations
  - Setting `canisters -> {asset_canister_id} -> declarations -> env_override to a string` in `dfx.json` will replace `process.env.DFX_NETWORK` with the string in the autogenerated declarations
- Write your own `createActor` constructor

### Interface ##
#### get_self ####
//dfx canister call rust_profile_backend get_self

dfx canister --network ic call $canisterId get_self

#### set_map_name   ####
dfx canister --network ic call $canisterId set_map_name '("2vxsx-fae")'

#### unset_map_name   ####
dfx canister --network ic call $canisterId unset_map_name

#### get_map_name   ####
dfx canister --network ic call $canisterId get_map_name

#### add  ####
dfx canister --network ic call $canisterId add '("111", "data1")'

#### update  ####
dfx canister --network ic call $canisterId update '("111", "data1")'

#### get  ####
dfx canister --network ic call $canisterId get '("111")'

#### remove  ####
dfx canister --network ic call $canisterId remove '("111")'

#### get_all  ####
dfx canister --network ic call $canisterId get_all
