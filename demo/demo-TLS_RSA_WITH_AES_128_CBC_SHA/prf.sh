# always use sha256
# usage prf secret_file label data_file out_size output
# example:
#   prf secret_file 'master secret' client_server_random 48 master_secret
set -e
hash_size=32
secret_file=$1
label=$2
data_file=$3
let out_size=$4
dir=${5:-.}
output=$5
dir=$output.dir

if [[ ! -e $secret_file ]];then
   echo "requires secret_file" >&2
   exit 1
fi
if [[ ! -e $data_file ]];then
  echo "requires data_file" >&2
   exit 1
fi

mkdir -p "$dir"

let 'iterations=out_size/hash_size + (out_size%hash_size==0?0:1)'

# function hmac DST_FILE SRC_FILE
# HMAC output 32 bytes per file
function hmac {
    # openssl dgst -sha256 -binary -mac hmac -macopt "hexkey:$hexkey" -out "$1" "$2"
    openssl dgst -sha256 -binary -hmac "$(cat "$secret_file")" -out "$1" "$2"
}

# seed
echo -n "$label" > "$dir/seed"
cat "$data_file" >> "$dir/seed"

cat "$dir/seed" > "$dir/A0"

i=1
while [[ $i -le $iterations ]];do
    # A(i) = hmac(A(i-1))
    hmac "$dir/A$i" "$dir/A$((i-1))"
    # P(i) = hmac(A(i) + seed)
    cat "$dir/A$i" "$dir/seed" > "$dir/A${i}_seed"
    hmac "$dir/P$i" "$dir/A${i}_seed"
    # result = concat
    cat "$dir/P${i}" >> "$dir/key"
    let i++
done

truncate -s "$out_size" "$dir/key"

cp "$dir/key" "$output"

hexdump -C "$output"

# keep this for debug purepose
rm -rf "$output.dir"