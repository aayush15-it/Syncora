#include "merklechain/scanner.hpp"
#include "merklechain/hash.hpp"
#include "merklechain/sync.hpp"
#include "merklechain/storage.hpp"
#include "merklechain/versioning.hpp"
#include "merklechain/web_server.hpp"
#include "merklechain/peer/peer_config.hpp"
#include "merklechain/peer/peer_service.hpp"
#include <iostream>
#include <limits>
#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>

static void help(){
    std::cout << "MerkleChain\n\n"
              << "Usage:\n"
              << "  merklechain.exe --local\n"
              << "  merklechain.exe --peer-host --config <path>   (run authenticated TLS peer host)\n"
              << "  merklechain.exe --peer-sync --config <path>   (connect and synchronize with peer)\n"
              << "  merklechain.exe --peer-help                   (display peer synchronization guide)\n"
              << "  merklechain.exe --dashboard [port]            (loopback-only local dashboard; default 47831)\n"
              << "  merklechain.exe --versions <folder>\n"
              << "  merklechain.exe --restore <folder> <version-id>\n"
              << "  merklechain.exe --network                     (not implemented; exits safely)\n"
              << "  merklechain.exe --help\n\n"
              << "Local metadata: <folder>/.merklechain/activity.sqlite3, baselines.sqlite3, objects/, and recovery/.\n";
}

static void peer_help() {
    std::cout << "MerkleChain Peer Synchronization\n\n"
              << "Usage:\n"
              << "  merklechain.exe --peer-host --config <config.json>\n"
              << "      Runs in Host daemon mode. Listens on configured bind_address:port,\n"
              << "      authenticates incoming client via mTLS and certificate fingerprint pin,\n"
              << "      exchanges manifests, negotiates bilateral plan, and executes verified\n"
              << "      file transfers and two-phase commit.\n"
              << "      NOTE: Host does NOT mutate any files simply upon connection;\n"
              << "      bilateral agreement and explicit authorization are strictly required.\n\n"
              << "  merklechain.exe --peer-sync --config <config.json>\n"
              << "      Runs in Client sync mode. Connects to configured host_address:port over TLS,\n"
              << "      authenticates host certificate pin, exchanges manifests, displays proposed plan,\n"
              << "      requires explicit user approval ('YES') before destructive or ambiguous actions,\n"
              << "      stages incoming files into verified staging artifacts, executes local commit,\n"
              << "      and advances bilateral baseline upon mutual verified commit.\n\n"
              << "  merklechain.exe --peer-help\n"
              << "      Displays this peer synchronization help message.\n\n"
              << "Configuration Schema (JSON):\n"
              << "  {\n"
              << "    \"schema_version\": 1,\n"
              << "    \"role\": \"host\" | \"client\",\n"
              << "    \"identity\": \"laptop-a\" | \"laptop-b\",\n"
              << "    \"sync_root\": \"C:/Path/To/SyncFolder\",\n"
              << "    \"port\": 47832,\n"
              << "    \"bind_address\": \"0.0.0.0\",      (required for host)\n"
              << "    \"host_address\": \"192.168.1.50\",   (required for client)\n"
              << "    \"certificate_file\": \"C:/certs/peer.crt\",\n"
              << "    \"private_key_file\": \"C:/certs/peer.key\",\n"
              << "    \"ca_file\": \"C:/certs/ca.crt\",\n"
              << "    \"expected_peer_sha256\": \"<64-hex-char SHA-256 fingerprint of peer leaf cert>\"\n"
              << "  }\n";
}

static std::string ask(const char* label){std::cout<<label;std::string s;std::getline(std::cin,s);return s;}
static bool overlaps(const mc::fs::path& a,const mc::fs::path& b){
    auto x=a.lexically_normal(),y=b.lexically_normal();auto ix=x.begin(),iy=y.begin();
    for(;ix!=x.end()&&iy!=y.end();++ix,++iy){auto sx=ix->string(),sy=iy->string();std::transform(sx.begin(),sx.end(),sx.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});std::transform(sy.begin(),sy.end(),sy.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});if(sx!=sy)return false;}
    return ix==x.end()||iy==y.end();
}
int main(int argc,char** argv){
    if(argc==2&&std::string(argv[1])=="--help"){help();return 0;}
    if(argc==2&&std::string(argv[1])=="--peer-help"){peer_help();return 0;}
    if(argc==2&&std::string(argv[1])=="--network"){std::cerr<<"Network Mode is not implemented in this build; no listener was started.\n";return 3;}
    if(argc>=2&&std::string(argv[1])=="--peer-host"){
        if(argc!=4||std::string(argv[2])!="--config"){
            std::cerr<<"Usage: merklechain.exe --peer-host --config <config.json>\n";return 2;
        }
        try{
            const auto config=mc::peer::load_peer_config(argv[3],mc::peer::Role::Host);
            const auto report=mc::peer::PeerService::run_host(config);
            if(!report.success){std::cerr<<"Peer Host failed: "<<report.error<<"\n";return 1;}
            std::cout<<"Peer Host completed successfully.\n";return 0;
        }catch(const std::exception& e){std::cerr<<"Peer Host error: "<<e.what()<<"\n";return 1;}
    }
    if(argc>=2&&std::string(argv[1])=="--peer-sync"){
        if(argc!=4||std::string(argv[2])!="--config"){
            std::cerr<<"Usage: merklechain.exe --peer-sync --config <config.json>\n";return 2;
        }
        try{
            const auto config=mc::peer::load_peer_config(argv[3],mc::peer::Role::Client);
            const auto report=mc::peer::PeerService::run_client(config);
            if(report.cancelled){std::cout<<"Peer sync was cancelled.\n";return 0;}
            if(!report.success){std::cerr<<"Peer sync failed: "<<report.error<<"\n";return 1;}
            std::cout<<"Peer sync completed successfully.\n";return 0;
        }catch(const std::exception& e){std::cerr<<"Peer sync error: "<<e.what()<<"\n";return 1;}
    }
    try{
        if(argc==2&&std::string(argv[1])=="--dashboard"){mc::run_web_server();return 0;}
        if(argc==3&&std::string(argv[1])=="--dashboard"){
            unsigned int port=0;const std::string value=argv[2];const auto parsed=std::from_chars(value.data(),value.data()+value.size(),port);
            if(parsed.ec!=std::errc{}||parsed.ptr!=value.data()+value.size()||port==0||port>65535)throw std::runtime_error("dashboard port must be an integer from 1 to 65535");
            mc::run_web_server(static_cast<std::uint16_t>(port));return 0;
        }
        if(argc==3&&std::string(argv[1])=="--versions"){
            auto folder=mc::fs::weakly_canonical(argv[2]);auto state=folder/".merklechain";if(!mc::fs::is_directory(folder)||!mc::fs::is_regular_file(state/"activity.sqlite3"))throw std::runtime_error("no MerkleChain version database exists for this folder");mc::VersionStore versions(state/"activity.sqlite3",state);for(const auto& version:versions.list_versions())std::cout<<version.record.id<<"  "<<version.label<<"  files="<<version.file_count<<"  root="<<version.record.integrity_hash<<"\n";return 0;
        }
        if(argc==4&&std::string(argv[1])=="--restore"){
            auto folder=mc::fs::weakly_canonical(argv[2]);auto state=folder/".merklechain";if(!mc::fs::is_directory(folder)||!mc::fs::is_regular_file(state/"activity.sqlite3"))throw std::runtime_error("no MerkleChain version database exists for this folder");mc::VersionStore versions(state/"activity.sqlite3",state);std::cout<<"Restore version "<<argv[3]<<" to "<<folder<<"? This replaces current files and removes paths absent from the version, while saving a recovery snapshot. Type YES: ";std::string confirmation;std::getline(std::cin,confirmation);if(confirmation!="YES"){std::cout<<"Restore cancelled.\n";return 0;}bool restored=versions.restore(argv[3],folder,true);std::cout<<(restored?"Version restored and verified.\n":"Restore did not pass final manifest verification; recovery data was retained.\n");return restored?0:1;
        }
        if(argc!=2||std::string(argv[1])!="--local"){help();return 2;}
        auto a=mc::fs::weakly_canonical(ask("Folder A (source): "));auto b=mc::fs::weakly_canonical(ask("Folder B (destination): "));
        if(overlaps(a,b))throw std::runtime_error("Folder selections must not overlap");
        if(!mc::fs::is_directory(a)||!mc::fs::is_directory(b))throw std::runtime_error("Both selected folders must already exist");
        std::cout<<"Scanning Folder A...\n";auto ma=mc::scan_folder(a);std::cout<<"Scanning Folder B...\n";auto mb=mc::scan_folder(b);
        for(const auto& w:ma.warnings)std::cerr<<"A warning: "<<w<<"\n";
        for(const auto& w:mb.warnings)std::cerr<<"B warning: "<<w<<"\n";
        if(!ma.complete||!mb.complete)throw std::runtime_error("Scan incomplete; no synchronization plan will be executed");
        auto jobs=mc::compare_manifests(ma,mb,a,b);std::cout<<"\nA Merkle root: "<<ma.merkle_root<<"\nB Merkle root: "<<mb.merkle_root<<"\nPlan (A -> B):\n";
        for(const auto& j:jobs)std::cout<<"  "<<mc::operation_name(j.operation)<<"  "<<j.relative_path<<(j.error.empty()?"":"  ["+j.error+"]")<<"\n";
        const bool changes=std::any_of(jobs.begin(),jobs.end(),[](const auto& j){return j.operation==mc::Operation::Add||j.operation==mc::Operation::Modify;});
        const bool deletions=std::any_of(jobs.begin(),jobs.end(),[](const auto& j){return j.operation==mc::Operation::Delete;});
        bool approved=false,deletions_confirmed=false;
        if(changes||deletions){std::cout<<"\nDestination-only paths are preserved. Approve planned changes? Type YES: ";approved=ask("")=="YES";if(!approved){std::cout<<"Cancelled; no destination changes made.\n";return 0;}}
        if(deletions){std::cout<<"DELETE operations remove destination paths after saving recovery copies. Type YES to confirm deletion: ";deletions_confirmed=ask("")=="YES";if(!deletions_confirmed){std::cout<<"Cancelled; no destination changes made.\n";return 0;}}
        auto internal=b/".merklechain";mc::ActivityStore store(internal/"activity.sqlite3");mc::VersionStore versions(internal/"activity.sqlite3",internal);const bool mutations=changes||deletions;std::string before_version;if(mutations)before_version=versions.create_snapshot(b,"before approved local synchronization");
        mc::FileManifest expected;expected.files=ma.files;for(const auto& file:mb.files)if(std::none_of(ma.files.begin(),ma.files.end(),[&](const auto& source){return source.relative_path==file.relative_path;}))expected.files.push_back(file);
        std::sort(expected.files.begin(),expected.files.end(),[](const auto& left,const auto& right){return left.relative_path<right.relative_path;});const auto expected_root=mc::merkle_root(expected.files);
        mc::SyncExecutionOptions execution;execution.authorization={approved,deletions_confirmed};execution.use_scheduler=true;execution.use_chunking=true;
        bool ok=mc::execute_plan(jobs,b,internal/"recovery",{},execution);for(const auto& j:jobs)store.record(j);
        auto final_manifest=mc::scan_folder(b);if(ok&&(!final_manifest.complete||final_manifest.merkle_root!=expected_root)){ok=false;std::cerr<<"Final destination Merkle root did not match the approved plan. Recovery data was retained.\n";}
        if(ok&&mutations){auto after=versions.create_snapshot(b,"after verified local synchronization",before_version);std::cout<<"Recovery versions saved: before="<<before_version<<" after="<<after<<"\n";}
        for(const auto& j:jobs)if(j.operation!=mc::Operation::Unchanged&&j.operation!=mc::Operation::Preserve)std::cout<<j.relative_path<<": "<<(j.verified?"verified":("failed: "+j.error))<<"\n";
        std::cout<<(ok?"Synchronization completed and verified.":"Synchronization partially failed; see activity database.")<<"\n";return ok?0:1;
    }catch(const std::exception& e){std::cerr<<"MerkleChain error: "<<e.what()<<"\n";return 1;}
}
