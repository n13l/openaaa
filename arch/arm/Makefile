# testing for a specific architecture or later rather impossible.
arch-$(CONFIG_CPU_32v7M)	=-D__LINUX_ARM_ARCH__=7 -march=armv7-m -Wa,-march=armv7-m
arch-$(CONFIG_CPU_32v7)		=-D__LINUX_ARM_ARCH__=7 $(call cc-option,-march=armv7-a,-march=armv5t -Wa$(comma)-march=armv7-a)
arch-$(CONFIG_CPU_32v6)		=-D__LINUX_ARM_ARCH__=6 $(call cc-option,-march=armv6,-march=armv5t -Wa$(comma)-march=armv6)
# Only override the compiler option if ARMv6. The ARMv6K extensions are
# always available in ARMv7
ifeq ($(CONFIG_CPU_32v6),y)
arch-$(CONFIG_CPU_32v6K)	=-D__LINUX_ARM_ARCH__=6 $(call cc-option,-march=armv6k,-march=armv5t -Wa$(comma)-march=armv6k)
endif
arch-$(CONFIG_CPU_32v5)		=-D__LINUX_ARM_ARCH__=5 $(call cc-option,-march=armv5te,-march=armv4t)
arch-$(CONFIG_CPU_32v4T)	=-D__LINUX_ARM_ARCH__=4 -march=armv4t
arch-$(CONFIG_CPU_32v4)		=-D__LINUX_ARM_ARCH__=4 -march=armv4
arch-$(CONFIG_CPU_32v3)		=-D__LINUX_ARM_ARCH__=3 -march=armv3

# Evaluate arch cc-option calls now
arch-y := $(arch-y)

KBUILD_DEFCONFIG := versatile_defconfig

# This selects how we optimise for the processor.
tune-$(CONFIG_CPU_ARM7TDMI)	=-mtune=arm7tdmi
tune-$(CONFIG_CPU_ARM720T)	=-mtune=arm7tdmi
tune-$(CONFIG_CPU_ARM740T)	=-mtune=arm7tdmi
tune-$(CONFIG_CPU_ARM9TDMI)	=-mtune=arm9tdmi
tune-$(CONFIG_CPU_ARM940T)	=-mtune=arm9tdmi
tune-$(CONFIG_CPU_ARM946E)	=$(call cc-option,-mtune=arm9e,-mtune=arm9tdmi)
tune-$(CONFIG_CPU_ARM920T)	=-mtune=arm9tdmi
tune-$(CONFIG_CPU_ARM922T)	=-mtune=arm9tdmi
tune-$(CONFIG_CPU_ARM925T)	=-mtune=arm9tdmi
tune-$(CONFIG_CPU_ARM926T)	=-mtune=arm9tdmi
tune-$(CONFIG_CPU_FA526)	=-mtune=arm9tdmi
tune-$(CONFIG_CPU_SA110)	=-mtune=strongarm110
tune-$(CONFIG_CPU_SA1100)	=-mtune=strongarm1100
tune-$(CONFIG_CPU_XSCALE)	=$(call cc-option,-mtune=xscale,-mtune=strongarm110) -Wa,-mcpu=xscale
tune-$(CONFIG_CPU_XSC3)		=$(call cc-option,-mtune=xscale,-mtune=strongarm110) -Wa,-mcpu=xscale
tune-$(CONFIG_CPU_FEROCEON)	=$(call cc-option,-mtune=marvell-f,-mtune=xscale)
tune-$(CONFIG_CPU_V6)		=$(call cc-option,-mtune=arm1136j-s,-mtune=strongarm)
tune-$(CONFIG_CPU_V6K)		=$(call cc-option,-mtune=arm1136j-s,-mtune=strongarm)

# Evaluate tune cc-option calls now
tune-y := $(tune-y)

ifeq ($(CONFIG_AEABI),y)
CFLAGS_ABI	:=-mabi=aapcs-linux -mno-thumb-interwork -mfpu=vfp
else
CFLAGS_ABI	:=$(call cc-option,-mapcs-32,-mabi=apcs-gnu) $(call cc-option,-mno-thumb-interwork,)
endif

ifeq ($(CONFIG_ARM_UNWIND),y)
CFLAGS_ABI	+=-funwind-tables
endif

# by CONFIG_* macro name.
machine-$(CONFIG_ARCH_ALPINE)		+= alpine
machine-$(CONFIG_ARCH_AT91)		+= at91
machine-$(CONFIG_ARCH_AXXIA)		+= axxia
machine-$(CONFIG_ARCH_BCM)		+= bcm
machine-$(CONFIG_ARCH_BERLIN)		+= berlin
machine-$(CONFIG_ARCH_CLPS711X)		+= clps711x
machine-$(CONFIG_ARCH_CNS3XXX)		+= cns3xxx
machine-$(CONFIG_ARCH_DAVINCI)		+= davinci
machine-$(CONFIG_ARCH_DIGICOLOR)	+= digicolor
machine-$(CONFIG_ARCH_DOVE)		+= dove
machine-$(CONFIG_ARCH_EBSA110)		+= ebsa110
machine-$(CONFIG_ARCH_EFM32)		+= efm32
machine-$(CONFIG_ARCH_EP93XX)		+= ep93xx
machine-$(CONFIG_ARCH_EXYNOS)		+= exynos
machine-$(CONFIG_ARCH_FOOTBRIDGE)	+= footbridge
machine-$(CONFIG_ARCH_GEMINI)		+= gemini
machine-$(CONFIG_ARCH_HIGHBANK)		+= highbank
machine-$(CONFIG_ARCH_HISI)		+= hisi
machine-$(CONFIG_ARCH_INTEGRATOR)	+= integrator
machine-$(CONFIG_ARCH_IOP13XX)		+= iop13xx
machine-$(CONFIG_ARCH_IOP32X)		+= iop32x
machine-$(CONFIG_ARCH_IOP33X)		+= iop33x
machine-$(CONFIG_ARCH_IXP4XX)		+= ixp4xx
machine-$(CONFIG_ARCH_KEYSTONE)		+= keystone
machine-$(CONFIG_ARCH_KS8695)		+= ks8695
machine-$(CONFIG_ARCH_LPC32XX)		+= lpc32xx
machine-$(CONFIG_ARCH_MESON)		+= meson
machine-$(CONFIG_ARCH_MMP)		+= mmp
machine-$(CONFIG_ARCH_MOXART)		+= moxart
machine-$(CONFIG_ARCH_MV78XX0)		+= mv78xx0
machine-$(CONFIG_ARCH_MVEBU)		+= mvebu
machine-$(CONFIG_ARCH_MXC)		+= imx
machine-$(CONFIG_ARCH_MEDIATEK)		+= mediatek
machine-$(CONFIG_ARCH_MXS)		+= mxs
machine-$(CONFIG_ARCH_NETX)		+= netx
machine-$(CONFIG_ARCH_NOMADIK)		+= nomadik
machine-$(CONFIG_ARCH_NSPIRE)		+= nspire
machine-$(CONFIG_ARCH_OMAP1)		+= omap1
machine-$(CONFIG_ARCH_OMAP2PLUS)	+= omap2
machine-$(CONFIG_ARCH_ORION5X)		+= orion5x
machine-$(CONFIG_ARCH_PICOXCELL)	+= picoxcell
machine-$(CONFIG_ARCH_PXA)		+= pxa
machine-$(CONFIG_ARCH_QCOM)		+= qcom
machine-$(CONFIG_ARCH_REALVIEW)		+= realview
machine-$(CONFIG_ARCH_ROCKCHIP)		+= rockchip
machine-$(CONFIG_ARCH_RPC)		+= rpc
machine-$(CONFIG_ARCH_S3C24XX)		+= s3c24xx
machine-$(CONFIG_ARCH_S3C64XX)		+= s3c64xx
machine-$(CONFIG_ARCH_S5PV210)		+= s5pv210
machine-$(CONFIG_ARCH_SA1100)		+= sa1100
machine-$(CONFIG_ARCH_SHMOBILE) 	+= shmobile
machine-$(CONFIG_ARCH_SIRF)		+= prima2
machine-$(CONFIG_ARCH_SOCFPGA)		+= socfpga
machine-$(CONFIG_ARCH_STI)		+= sti
machine-$(CONFIG_ARCH_SUNXI)		+= sunxi
machine-$(CONFIG_ARCH_TEGRA)		+= tegra
machine-$(CONFIG_ARCH_U300)		+= u300
machine-$(CONFIG_ARCH_U8500)		+= ux500
machine-$(CONFIG_ARCH_VERSATILE)	+= versatile
machine-$(CONFIG_ARCH_VEXPRESS)		+= vexpress
machine-$(CONFIG_ARCH_VT8500)		+= vt8500
machine-$(CONFIG_ARCH_W90X900)		+= w90x900
machine-$(CONFIG_ARCH_ZYNQ)		+= zynq
machine-$(CONFIG_PLAT_SPEAR)		+= spear

# Platform directory name.  This list is sorted alphanumerically
# by CONFIG_* macro name.
plat-$(CONFIG_ARCH_EXYNOS)	+= samsung
plat-$(CONFIG_ARCH_OMAP)	+= omap
plat-$(CONFIG_ARCH_S3C64XX)	+= samsung
plat-$(CONFIG_ARCH_S5PV210)	+= samsung
plat-$(CONFIG_PLAT_IOP)		+= iop
plat-$(CONFIG_PLAT_ORION)	+= orion
plat-$(CONFIG_PLAT_PXA)		+= pxa
plat-$(CONFIG_PLAT_S3C24XX)	+= samsung
plat-$(CONFIG_PLAT_VERSATILE)	+= versatile
