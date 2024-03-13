use class_group::primitives::cl_dl_public_setup::*;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{VerifiableSS, ShamirSecretSharing};
use curv::elliptic::curves::{Curve, Point, Scalar, Bls12_381_1};
use curv::BigInt;
use sha2::{Sha256, Digest}; 
use serde::{Deserialize, Serialize};
use crate::Error::{self, InvalidKey, InvalidSS};


const SECURITY: usize = 256;

pub struct Parameters {
    pub threshold: u16,   //t
    pub share_count: u16, //n
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keys<E: Curve = Bls12_381_1> {
    pub u_i: Scalar<E>,// 自选随机数
    pub y_i: Point<E>,// G*ui
    pub dk: PK,// 同态密钥对
    pub ek: SK,
    pub party_index: u16,// 参与者的序号
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyPrivate {
    u_i: Scalar<Bls12_381_1>,
    x_i: Scalar<Bls12_381_1>,// (t,n)分享的子秘密
    dk: SK,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenBroadcastMessage1 {
    pub e: PK,
    pub com: BigInt,
    //pub correct_key_proof: NiCorrectKeyProof,// 对同态密钥的公钥做证明
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenDecommitMessage1 {
    pub blind_factor: BigInt,
    pub y_i: Point<Bls12_381_1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedKeys {
    pub y: Point<Bls12_381_1>,//sum yi
    pub x_i: Scalar<Bls12_381_1>,
}

//方法实现
impl Keys{
    //初始化，随机选取ui，同态密钥对生成
    pub fn create(index: u16) -> Self {
        let u = Scalar::<Bls12_381_1>::random();
        let y = Point::generator() * &u;//就是g*ui
        const seed: &str =  "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"; 
        let group = CLGroup::new_from_setup(&1600, &BigInt::from_str_radix(seed, 10).unwrap());
        let (ek, dk) = group.keygen();//cl密钥生成
        Self {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
        }
    }

    //第一阶段的公开信息哈希承诺，同态公钥
    pub fn phase1_broadcast(
        &self,
    ) -> (KeyGenBroadcastMessage1, KeyGenDecommitMessage1) {
        let blind_factor = BigInt::sample(SECURITY);
        let com = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(//对随机数做一个哈希承诺
            &BigInt::from_bytes(self.y_i.to_bytes(true).as_ref()),
            &blind_factor,
        );
        let bcm1 = KeyGenBroadcastMessage1 {//公布第一阶段广播信息，包含同态公钥，随机数承诺和同态的公钥的证明
            e: self.dk.clone(),
            com,
        };
        let decom1 = KeyGenDecommitMessage1 {//解开承诺
            blind_factor,
            y_i: self.y_i.clone(),
        };
        (bcm1, decom1)
    }

    //Feldman vss
    #[allow(clippy::type_complexity)]
    pub fn phase1_verify_com_phase2_vss_distribute(
        &self,
        params: &Parameters,
        decom_vec: &[KeyGenDecommitMessage1],
        bc1_vec: &[KeyGenBroadcastMessage1],
    ) -> Result<(VerifiableSS<Bls12_381_1>, Vec<Scalar<Bls12_381_1>>, u16), Error> {
        // 长度验证
        assert_eq!(decom_vec.len(), usize::from(params.share_count));
        assert_eq!(bc1_vec.len(), usize::from(params.share_count));
        // 每位用户都验证收到的承诺
        let correct_key_correct_decom_all = (0..bc1_vec.len()).all(|i| {
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(decom_vec[i].y_i.to_bytes(true).as_ref()),
                &decom_vec[i].blind_factor,
            ) == bc1_vec[i].com
        });
        //根据(t,n)和参与者ui生成feldman vss，包含系数承诺和share
        let (vss_scheme, secret_shares) =
            VerifiableSS::share(params.threshold, params.share_count, &self.u_i);
        if correct_key_correct_decom_all {
            Ok((vss_scheme, secret_shares.to_vec(), self.party_index))
        } else {
            Err(InvalidKey)
        }
    }

    pub fn phase2_verify_vss_construct_keypair_phase3_pok_dlog(
        &self,
        params: &Parameters,
        y_vec: &[Point<Bls12_381_1>],
        secret_shares_vec: &[Scalar<Bls12_381_1>],
        vss_scheme_vec: &[VerifiableSS<Bls12_381_1>],
        index: u16,
    ) -> Result<(SharedKeys, DLogProof<Bls12_381_1, Sha256>), Error> {
        //长度验证
        assert_eq!(y_vec.len(), usize::from(params.share_count));
        assert_eq!(secret_shares_vec.len(), usize::from(params.share_count));
        assert_eq!(vss_scheme_vec.len(), usize::from(params.share_count));
        //share值验证，g^f(i)=
        let correct_ss_verify = (0..y_vec.len()).all(|i| {
            vss_scheme_vec[i]
                .validate_share(&secret_shares_vec[i], index)
                .is_ok()
                && vss_scheme_vec[i].commitments[0] == y_vec[i]
        });

        if correct_ss_verify {
            let y: Point<Bls12_381_1> = y_vec.iter().sum();//g*X
            let x_i: Scalar<Bls12_381_1> = secret_shares_vec.iter().sum();
            let dlog_proof = DLogProof::prove(&x_i);//公开的g^xi 
            Ok((SharedKeys { y, x_i }, dlog_proof))
        } else {
            Err(InvalidSS)
        }
    }

    pub fn verify_dlog_proofs(
        params: &Parameters,
        dlog_proofs_vec: &[DLogProof<Bls12_381_1, Sha256>],
        y_vec: &[Point<Bls12_381_1>],
    ) -> Result<(), Error> {
        assert_eq!(y_vec.len(), usize::from(params.share_count));
        assert_eq!(dlog_proofs_vec.len(), usize::from(params.share_count));

        let xi_dlog_verify =
            (0..y_vec.len()).all(|i| DLogProof::verify(&dlog_proofs_vec[i]).is_ok());

        if xi_dlog_verify {
            Ok(())
        } else {
            Err(InvalidKey)
        }
    } 
}

