import { readdir, readFile } from "node:fs/promises";

const root=JSON.parse(await readFile(new URL("../package.json",import.meta.url),"utf8"));
const packagesDirectory=new URL("../packages/",import.meta.url),directories=(await readdir(packagesDirectory,{withFileTypes:true})).filter((entry)=>entry.isDirectory()).map((entry)=>entry.name).sort(),manifests=[];
for(const directory of directories){const manifest=JSON.parse(await readFile(new URL(`${directory}/package.json`,packagesDirectory),"utf8"));manifests.push(manifest);
  if(typeof manifest.name!=="string"||!manifest.name.startsWith("@gostcrypto/"))throw new Error(`${directory}: invalid package name`);
  if(manifest.version!==root.version)throw new Error(`${manifest.name}: version ${manifest.version} differs from workspace ${root.version}`);
  if(manifest.author!==root.author)throw new Error(`${manifest.name}: author differs from workspace`);
  if(manifest.license!=="MIT")throw new Error(`${manifest.name}: license must be MIT`);
  if(manifest.publishConfig?.access!=="public")throw new Error(`${manifest.name}: scoped package must publish with public access`);
  if(!Array.isArray(manifest.files)||!manifest.files.includes("dist"))throw new Error(`${manifest.name}: dist is missing from files`);
  if(manifest.exports?.["."]===undefined)throw new Error(`${manifest.name}: root export is missing`);
}
const internal=new Set(manifests.map((manifest)=>manifest.name));
for(const manifest of manifests)for(const group of ["dependencies","peerDependencies","optionalDependencies"]){for(const [name,version] of Object.entries(manifest[group]??{}))if(internal.has(name)&&version!==root.version)throw new Error(`${manifest.name}: ${name} must use workspace release version ${root.version}`);}
if(process.argv.includes("--tag")){const tag=process.env.GITHUB_REF_NAME;if(tag!==`v${root.version}`)throw new Error(`release tag ${tag??"<missing>"} does not match v${root.version}`);}
console.log(`Validated ${manifests.length} publishable packages at version ${root.version}.`);
