using ASPNETIdentityCourse.Models.Entities;
using ASPNETIdentityCourse.Models.ViewModels;
using AutoMapper;

namespace ASPNETIdentityCourse.Mappings;

public class AccountMappingProfile: Profile
{
    public AccountMappingProfile()
    {
        CreateMap<RegisterViewModel, ApplicationUser>()
            .ForMember(dest => dest.Name, opt => opt.MapFrom(src => src.Name))
            .ForMember(dest => dest.Email, opt => opt.MapFrom(src => src.Email))
            .ForMember(dest => dest.UserName, opt => opt.MapFrom(src => src.Email));
    }
}