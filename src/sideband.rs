use anyhow::bail;

enum Channel {
    PackData,
    ProgressMessage,
    ErrorMessage,
}

struct PackData<'a> {
    _payload: &'a [u8],
    _channel: Channel,
}

impl<'a> TryFrom<&'a [u8]> for PackData<'a> {
    type Error = anyhow::Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            _payload: bytes.get(1..).ok_or(anyhow::anyhow!("no payload bytes"))?,
            _channel: match bytes
                .first()
                .ok_or(anyhow::anyhow!("not enough bytes to identify channel"))?
            {
                0x01 => Channel::PackData,
                0x02 => Channel::ProgressMessage,
                0x03 => Channel::ErrorMessage,
                b => bail!("invalid channel: {b:#x}"),
            },
        })
    }
}
